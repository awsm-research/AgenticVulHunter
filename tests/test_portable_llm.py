"""Offline provider contracts and agent failure semantics; no model credentials."""
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from agenticbughunter.config import Config, LLMConfig, load_config, validate_config
from agenticbughunter.config_edit import set_config_value
from agenticbughunter.llm import AgentRunner, LLMResponse, Tool, ToolRegistry, extract_json_value
from agenticbughunter.llm.client import create_client
from agenticbughunter.llm.providers import build_request, parse_response
from agenticbughunter.runlog import RunLogger

MESSAGES = [{'role': 'system', 'content': 'instructions'}, {'role': 'user', 'content': 'question'},
            {'role': 'user', 'content': 'final step'}]


class ProviderTests(unittest.TestCase):
    def test_openai_uses_only_text_and_supports_reasoning_model_options(self):
        c = LLMConfig(model='any-model', send_temperature=False, token_limit_field='max_completion_tokens', system_role='developer')
        url, headers, body = build_request(c, MESSAGES, 0, 400)
        self.assertTrue(url.endswith('/v1/chat/completions'))
        self.assertEqual(body['max_completion_tokens'], 400)
        self.assertEqual(body['messages'][0]['role'], 'developer')
        self.assertNotIn('temperature', body)
        self.assertNotIn('tools', body)
        self.assertEqual(MESSAGES[0]['role'], 'system')

    def test_anthropic_moves_system_and_merges_adjacent_turns(self):
        c = LLMConfig(provider='anthropic', base_url='https://api.anthropic.com/v1', api_key='test-key')
        url, headers, body = build_request(c, MESSAGES, 0, 400)
        self.assertEqual(url, 'https://api.anthropic.com/v1/messages')
        self.assertEqual(headers['x-api-key'], 'test-key')
        self.assertEqual(body['system'], 'instructions')
        self.assertEqual(body['messages'], [{'role': 'user', 'content': 'question\n\nfinal step'}])
        self.assertNotIn('tools', body)

    def test_gemini_maps_turns_and_does_not_put_key_in_url(self):
        c = LLMConfig(provider='gemini', base_url='https://generativelanguage.googleapis.com/v1beta',
                      model='models/example', api_key='test-key', extra_body={'generationConfig': {'topP': 0.9}})
        url, headers, body = build_request(c, MESSAGES + [{'role': 'assistant', 'content': '{}'}], 0, 400)
        self.assertTrue(url.endswith('/models/example:generateContent'))
        self.assertNotIn('test-key', url)
        self.assertEqual(headers['x-goog-api-key'], 'test-key')
        self.assertEqual(body['contents'][-1]['role'], 'model')
        self.assertEqual(body['generationConfig']['maxOutputTokens'], 400)
        self.assertEqual(body['generationConfig']['topP'], 0.9)
        self.assertNotIn('tools', body)

    def test_response_normalization_ignores_non_answer_blocks(self):
        cases = [
            ('openai', {'choices': [{'message': {'content': [{'type': 'text', 'text': '{}'}]}}]}),
            ('anthropic', {'content': [{'type': 'thinking', 'thinking': 'private'}, {'type': 'text', 'text': '{}'}]}),
            ('gemini', {'candidates': [{'finishReason': 'STOP', 'content': {'parts': [{'thought': True, 'text': 'private'}, {'text': '{}'}]}}]}),
        ]
        for provider, raw in cases:
            with self.subTest(provider=provider):
                self.assertEqual(parse_response(provider, raw)[0], '{}')

    def test_truncation_refusal_empty_and_native_tool_calls_are_errors(self):
        cases = [
            ('openai', {'choices': [{'finish_reason': 'length', 'message': {'content': '{}'}}]}),
            ('openai', {'choices': [{'message': {'content': '', 'refusal': 'no'}}]}),
            ('openai', {'choices': [{'message': {'content': '{}', 'tool_calls': [{}]}}]}),
            ('openai', {'choices': [{'message': {'content': ''}}]}),
            ('anthropic', {'stop_reason': 'max_tokens', 'content': [{'type': 'text', 'text': '{}'}]}),
            ('gemini', {'candidates': [{'finishReason': 'SAFETY'}]}),
            ('gemini', {'candidates': []}),
        ]
        for provider, raw in cases:
            with self.subTest(provider=provider, raw=raw), self.assertRaises(ValueError):
                parse_response(provider, raw)

    def test_retry_transient_http_then_success(self):
        client = create_client(LLMConfig(max_retries=1, retry_backoff_seconds=0))
        response = io.BytesIO(b'{"choices":[{"message":{"content":"{}"}}]}')
        error = urllib.error.HTTPError('https://example.invalid', 429, 'slow', {}, io.BytesIO(b'rate limited'))
        with patch.object(client._opener, 'open', side_effect=[error, response]) as mocked:
            result = client.chat(MESSAGES)
        self.assertEqual(result.content, '{}')
        self.assertEqual(mocked.call_count, 2)

    def test_auth_error_is_not_retried_and_key_is_redacted(self):
        client = create_client(LLMConfig(api_key='sensitive-key'))
        error = urllib.error.HTTPError('https://example.invalid', 401, 'auth', {}, io.BytesIO(b'sensitive-key invalid'))
        with patch.object(client._opener, 'open', side_effect=error) as mocked:
            with self.assertRaises(RuntimeError) as caught:
                client.chat(MESSAGES)
        self.assertNotIn('sensitive-key', str(caught.exception))
        self.assertEqual(mocked.call_count, 1)

    def test_context_budget_fails_before_network(self):
        client = create_client(LLMConfig(max_input_chars=2))
        with patch.object(client._opener, 'open') as mocked, self.assertRaises(RuntimeError):
            client.chat(MESSAGES)
        mocked.assert_not_called()

    def test_export_environment_and_nested_config(self):
        with patch.dict(os.environ, {'ABH_LLM_PROVIDER': 'gemini', 'ABH_LLM_MODEL': 'custom',
                                     'ABH_LLM_EXTRA_BODY': '{"generationConfig":{"topP":0.8}}'}, clear=True):
            cfg = load_config()
        self.assertEqual(cfg.llm.provider, 'gemini')
        self.assertEqual(cfg.llm.extra_body['generationConfig']['topP'], 0.8)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'settings.toml'
            set_config_value(path, 'llm.extra_body', '{"generationConfig":{"topP":0.8}}')
            self.assertEqual(load_config(path, use_environment=False).llm.extra_body['generationConfig']['topP'], 0.8)

    def test_config_rejects_nonfinite_and_native_tool_overrides(self):
        for config in [Config(llm=LLMConfig(temperature=float('nan'))),
                       Config(llm=LLMConfig(extra_body={'tools': []})),
                       Config(llm=LLMConfig(base_url='https://example.invalid/v1?key=secret'))]:
            with self.assertRaises(ValueError):
                validate_config(config)

    def test_environment_cannot_mask_invalid_config_edit(self):
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {'ABH_PIPELINE_MAX_CANDIDATES': '3'}):
            path = Path(td) / 'config.toml'
            with self.assertRaises(ValueError):
                set_config_value(path, 'pipeline.max_candidates', '-1')
            self.assertFalse(path.exists())


class ScriptedClient:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.messages = []

    def chat(self, messages, **kwargs):
        self.messages.append(json.loads(json.dumps(messages)))
        return LLMResponse(next(self.replies), {}, {}, 0)


class AgentTests(unittest.TestCase):
    def run_agent(self, replies, steps=4):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        logger = RunLogger(root)
        self.addCleanup(logger.close)
        self.calls = []
        tool = Tool('read_file', 'read a file', {'path': 'string'}, lambda args: self.calls.append(args) or {'text': 'evidence'})
        client = ScriptedClient(replies)
        runner = AgentRunner(client, ToolRegistry([tool]), logger, stage='test', max_steps=steps, artifact_dir=root / 'stage')
        return runner, client

    def test_observation_roundtrip_and_wrapped_final(self):
        runner, client = self.run_agent(['{"type":"tool","tool":"read_file","arguments":{"path":"a.py"}}',
                                         '{"type":"final","answer":{"done":true}}'])
        self.assertEqual(runner.run('instructions', 'input'), {'done': True})
        self.assertEqual(self.calls, [{'path': 'a.py'}])
        self.assertIn('evidence', client.messages[1][-1]['content'])
        self.assertTrue(all(m['role'] in {'user', 'assistant', 'system'} for m in client.messages[1]))

    def test_malformed_array_never_salvaged(self):
        with self.assertRaises(ValueError):
            extract_json_value('Here is the result: [{broken}, {"valid":true}]')
        runner, _ = self.run_agent(['[{broken}, {"valid":true}]', '[]'])
        self.assertEqual(runner.run('s', 'u'), [])
        self.assertEqual(self.calls, [])

    def test_multiple_actions_not_executed(self):
        tool = '{"type":"tool","tool":"read_file","arguments":{}}'
        runner, _ = self.run_agent([tool + '\n' + tool, '[]'])
        self.assertEqual(runner.run('s', 'u'), [])
        self.assertEqual(self.calls, [])

    def test_invalid_arguments_return_observation(self):
        runner, client = self.run_agent(['{"type":"tool","tool":"read_file","arguments":[]}', '[]'])
        runner.run('s', 'u')
        self.assertEqual(self.calls, [])
        self.assertIn('arguments must be a JSON object', client.messages[1][-1]['content'])

    def test_last_step_does_not_execute_tool(self):
        runner, _ = self.run_agent(['{"type":"tool","tool":"read_file","arguments":{}}'], steps=1)
        with self.assertRaisesRegex(RuntimeError, 'no tool was executed'):
            runner.run('s', 'u')
        self.assertEqual(self.calls, [])

    def test_unknown_tool_cannot_run(self):
        runner, client = self.run_agent(['{"type":"tool","tool":"shell","arguments":{"command":"touch x"}}', '[]'])
        runner.run('s', 'u')
        self.assertEqual(self.calls, [])
        self.assertIn('Unknown tool', client.messages[1][-1]['content'])

    def test_wrapped_null_and_exhaustion_fail(self):
        runner, _ = self.run_agent(['{"type":"final","answer":null}'], steps=1)
        with self.assertRaisesRegex(RuntimeError, 'without a valid final answer'):
            runner.run('s', 'u')

    def test_fenced_json_and_leading_thinking(self):
        self.assertEqual(extract_json_value('```json\n[]\n```'), [])
        self.assertEqual(extract_json_value('<think>consider {invalid}</think>\n[]'), [])


if __name__ == '__main__':
    unittest.main()
