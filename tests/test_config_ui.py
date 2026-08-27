from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agenticbughunter.config import Config, load_config
from agenticbughunter.config_edit import get_config_value, set_config_value
from agenticbughunter.cli import _config_path, _project_config_path
from agenticbughunter.models import Finding, PipelineResult, StageResult
from agenticbughunter.pipeline import SecureReviewPipeline
from agenticbughunter.ui import TerminalUI, stage_output_summary


class ConfigAndUITests(unittest.TestCase):
    def test_abh_environment_override_changes_pipeline_setting(self) -> None:
        with patch.dict(os.environ, {"ABH_PIPELINE_CONFIDENCE_THRESHOLD": "0.83"}, clear=False):
            cfg = load_config()
        self.assertEqual(cfg.pipeline.confidence_threshold, 0.83)

    def test_abh_boolean_environment_override(self) -> None:
        with patch.dict(os.environ, {"ABH_PIPELINE_BLOCK_ON_FINDINGS": "false"}, clear=False):
            cfg = load_config()
        self.assertFalse(cfg.pipeline.block_on_findings)


    def test_ui_settings_load_from_toml(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / ".agenticbughunter.toml"
            path.write_text(
                "[ui]\nbanner = false\nlive_progress = false\nshow_config = false\nshow_stage_details = false\n",
                encoding="utf-8",
            )
            cfg = load_config(path)
        self.assertFalse(cfg.ui.banner)
        self.assertFalse(cfg.ui.live_progress)
        self.assertFalse(cfg.ui.show_config)
        self.assertFalse(cfg.ui.show_stage_details)

    def test_abh_config_selects_alternate_toml(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            alt = repo / "configs" / "ablation.toml"
            alt.parent.mkdir()
            alt.write_text("[pipeline]\nmax_candidates = 3\n", encoding="utf-8")
            with patch.dict(os.environ, {"ABH_CONFIG": "configs/ablation.toml"}, clear=False):
                selected = _config_path(repo, None)
                writable = _project_config_path(repo, None)
            self.assertEqual(selected, alt.resolve())
            self.assertEqual(writable, alt.resolve())

    def test_ui_environment_override(self) -> None:
        with patch.dict(os.environ, {"ABH_UI_BANNER": "false"}, clear=False):
            cfg = load_config()
        self.assertFalse(cfg.ui.banner)

    def test_config_set_preserves_other_content(self) -> None:
        original = (
            "# project settings\n\n"
            "[pipeline]\n"
            "max_candidates = 5\n"
            "confidence_threshold = 0.75\n\n"
            "[llm]\n"
            'model = "qwen3-coder:30b"\n'
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / ".agenticbughunter.toml"
            path.write_text(original, encoding="utf-8")
            value = set_config_value(path, "pipeline.confidence_threshold", "0.81")
            text = path.read_text(encoding="utf-8")
            cfg = load_config(path)
        self.assertEqual(value, 0.81)
        self.assertIn("# project settings", text)
        self.assertIn("max_candidates = 5", text)
        self.assertIn("confidence_threshold = 0.81", text)
        self.assertEqual(cfg.pipeline.confidence_threshold, 0.81)

    def test_config_set_can_append_missing_field(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / ".agenticbughunter.toml"
            path.write_text("[pipeline]\nmax_candidates = 5\n", encoding="utf-8")
            set_config_value(path, "pipeline.max_comments", "7")
            cfg = load_config(path)
        self.assertEqual(get_config_value(cfg, "pipeline.max_comments"), 7)

    def test_stage_summary_reports_counts(self) -> None:
        stage = StageResult(
            "stage4_judge",
            [
                {"cwe_assessments": [{"verdict": "supported"}, {"verdict": "rejected"}]},
                {"cwe_assessments": [{"verdict": "supported"}]},
            ],
            500,
        )
        self.assertEqual(stage_output_summary(stage), "3 assessed, 2 supported")

    def test_progress_callback_failure_does_not_affect_pipeline(self) -> None:
        def broken_progress(_event, _payload):
            raise RuntimeError("terminal unavailable")

        pipeline = SecureReviewPipeline(Config(), progress=broken_progress)
        pipeline._emit("stage_started", stage="stage1_candidates", index=1)

    def test_terminal_ui_renders_stage_ticks_and_result(self) -> None:
        stream = io.StringIO()
        ui = TerminalUI(stream=stream, color=False)
        ui.progress_event(
            "pipeline_started",
            {
                "repo": "/tmp/project",
                "base": "main",
                "head": "HEAD",
                "model": "qwen3-coder:30b",
                "threshold": 0.75,
            },
        )
        ui.progress_event("stage_started", {"stage": "stage1_candidates", "index": 1})
        ui.progress_event(
            "stage_completed",
            {"stage": "stage1_candidates", "index": 1, "duration_ms": 1200, "output": [{}, {}, {}]},
        )
        finding = Finding(
            candidate_id="candidate-1",
            filepath="app.py",
            changed_line=12,
            statement="os.system(user_input)",
            cwe_id="CWE-78",
            cwe_name="OS Command Injection",
            final_score=0.91,
            verdict="supported",
            review_comment="Untrusted input reaches a shell command.",
            assessment={"change_type": "A"},
        )
        ui.final_result(PipelineResult("run-1", "block", [finding], [], "/tmp/run-1", []))
        output = stream.getvalue()
        self.assertIn("○ 1/5  Candidate localisation", output)
        self.assertIn("✓ 1/5  Candidate localisation", output)
        self.assertIn("BLOCK  1 supported finding(s)", output)
        self.assertIn("CWE-78", output)


if __name__ == "__main__":
    unittest.main()
