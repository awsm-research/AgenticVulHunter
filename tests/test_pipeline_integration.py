"""Exercise all five stages with real Git/BM25 and a deterministic text model.

These tests verify orchestration and contracts, not vulnerability accuracy.
"""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from agenticbughunter.config import Config
from agenticbughunter.git import resolve_default_base
from agenticbughunter.llm import LLMResponse
from agenticbughunter.pipeline import SecureReviewPipeline, PipelineExecutionError
from agenticbughunter.runlog import RunLogger
from agenticbughunter.stages.scoring import raw_score, _RELATIONSHIP_CAPS, _CONTRADICTION_CAPS


class ResearchFixtureModel:
    def __init__(self, invalid_location=False):
        self.invalid_location = invalid_location
        self.seen_stages = []

    def chat(self, messages, metadata=None, **kwargs):
        stage = metadata['stage']
        self.seen_stages.append(stage)
        user = next(m['content'] for m in messages if m['role'] == 'user')
        if stage.startswith('stage1'):
            answer = [{'filepath': 'app.py', 'changed_line': 999 if self.invalid_location else 2,
                       'statement': 'untrusted statement must be canonicalized', 'change_type': 'A',
                       'selection_reason': 'Untrusted command reaches os.system', 'security_relevance_score': 0.9}]
        elif stage.startswith('stage2'):
            answer = json.loads(user.split('CANDIDATE INPUT:\n', 1)[1])
            answer['mechanism_summary'] = 'Untrusted input directly reaches a shell command'
        elif stage.startswith('stage3'):
            rules = json.loads(user.split('INITIAL BM25 RULES (request #1, already executed by the program):\n', 1)[1])
            if not rules:
                raise AssertionError('BM25 fixture must produce real rules')
            answer = {'hypotheses': [{'cwe_id': rules[0]['cwe_id'], 'cwe_name': rules[0]['cwe_name'],
                                      'fit_reason': 'Test fixture hypothesis from actual retrieved rule'}]}
        elif stage.startswith('stage4'):
            payload = json.loads(user.split('PAIR INPUT:\n', 1)[1])
            candidate = payload['candidate']
            answer = {k: candidate[k] for k in ('candidate_id', 'filepath', 'changed_line', 'statement')}
            answer.update(cwe_id=payload['target_cwe']['cwe_id'], cwe_name=payload['target_cwe']['cwe_name'],
                          cwe_relationship='exact', contradiction_severity='none',
                          category_scores={k: {'score': 0.9, 'evidence': 'Deterministic test fixture evidence'} for k in
                                           ('exact_cwe_mechanism', 'connection', 'diff_causality', 'security_control', 'concrete_impact')},
                          review_comment='Test fixture: user input reaches a shell command.', unresolved_facts=[])
        else:
            raise AssertionError(stage)
        return LLMResponse(json.dumps(answer), {}, {}, 0)


class PipelineIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'commit.gpgsign', 'false')
        (self.repo / 'app.py').write_text('import os\nprint("safe")\n')
        self.git('add', 'app.py')
        self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD')
        (self.repo / 'app.py').write_text('import os\nos.system(input())\n')
        self.git('commit', '-qam', 'head')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.STDOUT, text=True).strip()

    def test_five_stages_run_with_injected_provider_and_real_local_retrieval(self):
        model = ResearchFixtureModel()
        (self.repo / 'untracked.txt').write_text('preserve this')
        result = SecureReviewPipeline(Config(), client=model).run(self.repo, base=self.base)
        self.assertEqual(result.status, 'block')
        self.assertEqual(len(result.stages), 5)
        self.assertEqual(result.comments[0]['line_snippet'], 'os.system(input())')
        self.assertEqual(result.comments[0]['line_number'], 2)
        self.assertTrue(any(x.startswith('stage4') for x in model.seen_stages))
        self.assertEqual((self.repo / 'untracked.txt').read_text(), 'preserve this')
        self.assertEqual(len(self.git('worktree', 'list').splitlines()), 1)
        provenance = json.loads((Path(result.run_dir) / 'provenance.json').read_text())
        self.assertEqual(provenance['base_sha'], self.base)
        self.assertEqual(len(provenance['prompt_sha256']), 4)
        config = json.loads((Path(result.run_dir) / 'config.json').read_text())
        self.assertEqual(config['llm']['api_key'], '***REDACTED***')
        self.assertEqual(config['llm']['max_tokens'], 6000)

    def test_invalid_candidate_is_error_not_clean_review(self):
        with self.assertRaises(PipelineExecutionError) as caught:
            SecureReviewPipeline(Config(), client=ResearchFixtureModel(invalid_location=True)).run(self.repo, base=self.base)
        result = json.loads((caught.exception.run_dir / 'result.json').read_text())
        self.assertEqual(result['status'], 'error')
        self.assertEqual(len(self.git('worktree', 'list').splitlines()), 1)

    def test_default_base_follows_requested_head_not_working_head(self):
        self.git('commit', '--allow-empty', '-qm', 'later')
        self.assertEqual(resolve_default_base(self.repo, head='HEAD~1'), 'HEAD~1~1')

    def test_identical_tree_does_not_call_model(self):
        head = self.git('rev-parse', 'HEAD')
        self.git('commit', '--allow-empty', '-qm', 'same tree')
        model = ResearchFixtureModel()
        result = SecureReviewPipeline(Config(), client=model).run(self.repo, base=head)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(model.seen_stages, [])

    def test_divergent_base_records_actual_diff_base(self):
        head = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-qb', 'divergent', self.base)
        (self.repo / 'app.py').write_text('import os\nprint("different base branch")\n')
        self.git('commit', '-qam', 'divergent base')
        selected = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', '--detach', head)
        result = SecureReviewPipeline(Config(), client=ResearchFixtureModel()).run(self.repo, base=selected, head=head)
        provenance = json.loads((Path(result.run_dir) / 'provenance.json').read_text())
        self.assertEqual(provenance['base_sha'], selected)
        self.assertEqual(provenance['diff_base_sha'], self.base)

    def test_scoring_policy_preserved_and_non_numeric_scores_fail(self):
        values = {k: {'score': 1.0} for k in
                  ('exact_cwe_mechanism', 'connection', 'diff_causality', 'security_control', 'concrete_impact')}
        self.assertEqual(raw_score({'category_scores': values}), 1)
        self.assertEqual(min(raw_score({'category_scores': values}), _RELATIONSHIP_CAPS['partial']), .59)
        self.assertEqual(_CONTRADICTION_CAPS['fatal'], .29)
        for invalid in (True, float('nan'), float('inf'), -1, 2):
            values['connection']['score'] = invalid
            with self.assertRaises(ValueError):
                raw_score({'category_scores': values})


if __name__ == '__main__':
    unittest.main()
