from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..config import BM25Config
from ..llm.agent import Tool
from ..runlog import RunLogger


class BM25Client:
    """Adapter for the user's existing BM25/SAST retriever.

    This package intentionally contains NO BM25 ranking implementation.
    It only calls the existing service using the contract already used by the
    staged project: {"items": [candidate], "top_k": N}.
    """

    def __init__(self, config: BM25Config, logger: RunLogger):
        self.config = config
        self.logger = logger
        if not self.config.endpoint:
            raise ValueError(
                "BM25 endpoint is not configured. Set [bm25].endpoint or SAST_RETRIEVER_URL."
            )

    def search(self, item: dict[str, Any], top_k: int) -> dict[str, Any]:
        top_k = min(max(1, int(top_k)), 20)
        payload = {"items": [item], "top_k": top_k}
        req = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                raw_text = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"BM25 endpoint returned HTTP {exc.code}: {detail[:1000]}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise RuntimeError(f"Unable to reach BM25 endpoint {self.config.endpoint}: {exc}") from exc
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"BM25 endpoint returned invalid JSON: {raw_text[:1000]}") from exc
        self.logger.event("bm25_call", {
            "endpoint": self.config.endpoint,
            "top_k": top_k,
            "duration_ms": (time.monotonic() - started) * 1000.0,
            "request": payload,
            "response": data,
        })
        return data


def compact_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    predictions = data.get("predictions") if isinstance(data, dict) else None
    prediction = predictions[0] if isinstance(predictions, list) and predictions and isinstance(predictions[0], dict) else {}
    rules = prediction.get("top_sast_rules") if isinstance(prediction, dict) else []
    compact: list[dict[str, Any]] = []
    if not isinstance(rules, list):
        return compact
    for rank, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            continue
        compact.append({
            "rank": rank,
            "rule_id": rule.get("rule_id") or rule.get("id"),
            "cwe_id": rule.get("cwe_id") or rule.get("cwe"),
            "cwe_name": rule.get("cwe_name"),
            "score": rule.get("score") or rule.get("relative_bm25") or rule.get("raw_bm25"),
            "description": str(rule.get("description") or rule.get("reason") or rule.get("message") or "")[:300],
        })
    return compact


def make_bm25_tool(
    client: BM25Client,
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
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {
            "request_number": state["count"],
            "top_k": top_k,
            "rules": compact_rules(data),
            "full_response_saved_to": path.name,
        }

    return Tool(
        "bm25_search",
        "Query the configured existing BM25/SAST retriever. Retrieval is a search signal, not ground truth.",
        {
            "retrieval_query": "object with grounded mechanism_summary/source/sensitive_operation/missing_control/impact/mechanism_keywords; may be empty on first request",
            "top_k": "integer 1..20",
        },
        handler,
    )
