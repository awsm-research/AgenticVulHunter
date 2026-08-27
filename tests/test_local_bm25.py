from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agenticbughunter.bm25 import DEFAULT_MODEL_DIR, SASTRetriever, model_exists
from agenticbughunter.config import BM25Config, load_config
from agenticbughunter.runlog import RunLogger
from agenticbughunter.tools.bm25 import BM25Retriever


class LocalBM25Tests(unittest.TestCase):
    def test_bundled_model_is_available(self) -> None:
        self.assertTrue(model_exists(DEFAULT_MODEL_DIR))
        retriever = SASTRetriever(DEFAULT_MODEL_DIR)
        self.assertEqual(retriever.metadata.get("algorithm"), "rule_bm25_cwe_retriever")
        self.assertEqual(len(retriever.rules), 314)
        self.assertEqual(retriever.metadata.get("cwe_count"), 132)

    def test_command_injection_retrieves_cwe_78_first(self) -> None:
        item = {
            "filepath": "bug.py",
            "changed_line": 4,
            "statement": "os.system(user_input)",
            "language": "python",
            "operation_type": "command_execution",
            "selection_reason": "A function parameter is passed directly to os.system without validation or escaping.",
            "source_summary": "user_input is a function parameter with unresolved trust origin",
            "sink_summary": "os.system executes a shell command",
            "guard_summary": "no validation or shell escaping is visible",
            "risk_pattern": "untrusted input may reach shell command execution",
            "called_apis": ["os.system"],
            "context_summary": "execute_command passes user_input directly to os.system",
        }

        with tempfile.TemporaryDirectory() as td:
            logger = RunLogger(Path(td))
            try:
                client = BM25Retriever(BM25Config(), logger)
                result = client.search(item, 10)
            finally:
                logger.close()

        predictions = result["predictions"]
        self.assertEqual(len(predictions), 1)
        rules = predictions[0]["top_sast_rules"]
        self.assertTrue(rules)
        self.assertEqual(rules[0]["cwe_id"], "CWE-78")
        self.assertEqual(rules[0]["rule_id"], "py/shell-command-constructed-from-input")


    def test_legacy_http_fields_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "legacy.toml"
            path.write_text(
                '[bm25]\n'
                'endpoint = "http://127.0.0.1:5056/predict"\n'
                'timeout_seconds = 120\n'
                'top_k = 7\n'
                'max_requests_per_candidate = 3\n',
                encoding="utf-8",
            )
            cfg = load_config(path)
        self.assertEqual(cfg.bm25.top_k, 7)
        self.assertEqual(cfg.bm25.max_requests_per_candidate, 3)
        self.assertFalse(hasattr(cfg.bm25, "endpoint"))

    def test_bm25_config_has_no_endpoint(self) -> None:
        cfg = BM25Config()
        self.assertEqual(cfg.top_k, 10)
        self.assertFalse(hasattr(cfg, "endpoint"))


if __name__ == "__main__":
    unittest.main()
