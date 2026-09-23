from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..bm25 import RULES_FILE, SASTRetriever, item_language, model_exists
from ..config import BM25Config
from ..llm.agent import Tool
from ..runlog import RunLogger


class BM25Retriever:
    """Local BM25 adapter used by Stage 3."""

    def __init__(self, config: BM25Config, logger: RunLogger):
        self.config = config
        self.logger = logger
        if not model_exists(RULES_FILE):
            raise RuntimeError("Bundled bm25/rules.json is missing or invalid")
        self.retriever = SASTRetriever(RULES_FILE)

    def search(self, item: dict[str, Any], top_k: int) -> dict[str, Any]:
        top_k = min(max(1, int(top_k)), 20)
        started = time.monotonic()
        rules = self.retriever.rank(item, top_k=top_k)
        data = {
            "predictions": [
                {
                    **item,
                    "language": item_language(item),
                    "retrieval_skipped": False,
                    "retrieval_skip_reason": None,
                    "top_sast_rules": rules,
                }
            ]
        }
        self.logger.event(
            "bm25_call",
            {
                "mode": "local",
                "algorithm": "rule_bm25_cwe_retriever",
                "top_k": top_k,
                "duration_ms": (time.monotonic() - started) * 1000.0,
                "request": {"items": [item], "top_k": top_k},
                "response": data,
            },
        )
        return data

    def status(self) -> dict[str, Any]:
        return {
            "mode": "local",
            "algorithm": "rule_bm25_cwe_retriever",
            "rules": len(self.retriever.rules),
            "cwes": self.retriever.cwe_count,
        }


BM25Client = BM25Retriever


def compact_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    predictions = data.get("predictions") if isinstance(data, dict) else None
    prediction = (
        predictions[0]
        if isinstance(predictions, list)
        and predictions
        and isinstance(predictions[0], dict)
        else {}
    )
    rules = prediction.get("top_sast_rules") if isinstance(prediction, dict) else []
    if not isinstance(rules, list):
        return []

    compact: list[dict[str, Any]] = []
    for rank, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            continue
        compact.append(
            {
                "rank": rank,
                "rule_id": rule.get("rule_id") or rule.get("id"),
                "cwe_id": rule.get("cwe_id") or rule.get("cwe"),
                "cwe_name": rule.get("cwe_name"),
                "score": (
                    rule.get("score")
                    or rule.get("relative_bm25")
                    or rule.get("raw_bm25")
                    or rule.get("raw_bm25_score")
                ),
                "description": str(
                    rule.get("description")
                    or rule.get("reason")
                    or rule.get("message")
                    or ""
                )[:300],
            }
        )
    return compact


def make_bm25_tool(
    client: BM25Retriever,
    base_item: dict[str, Any],
    artifact_dir: Path,
    max_requests: int,
    initial_count: int = 0,
) -> Tool:
    state = {"count": int(initial_count)}

    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if state["count"] >= max_requests:
            raise RuntimeError(f"BM25 request budget exhausted ({max_requests})")

        state["count"] += 1
        top_k = int(args.get("top_k") or client.config.top_k)
        query = args.get("retrieval_query") or {}
        if not isinstance(query, dict):
            raise ValueError("retrieval_query must be a JSON object")

        item = dict(base_item)
        if query:
            item["retrieval_query"] = query

        data = client.search(item, top_k)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / f"bm25_response_{state['count']}.json"
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return {
            "request_number": state["count"],
            "top_k": top_k,
            "rules": compact_rules(data),
            "full_response_saved_to": path.name,
        }

    return Tool(
        "bm25_search",
        "Query the bundled BM25 security rules. Retrieval is a search signal, not ground truth.",
        {
            "retrieval_query": (
                "object with mechanism_summary/source/sensitive_operation/"
                "missing_control/impact/mechanism_keywords; may be empty initially"
            ),
            "top_k": "integer 1..20",
        },
        handler,
    )
