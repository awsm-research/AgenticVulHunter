from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import Stage
from ..config import Config
from ..llm import AgentRunner, ChatClient, ToolRegistry
from ..resources import prompt
from ..runlog import RunLogger
from ..tools.bm25 import BM25Retriever, compact_rules, make_bm25_tool


def _normalise_cwe(value: Any) -> str:
    text = str(value or "").upper().strip()
    m = re.search(r"(?:CWE[-_ ]?)?(\d+)", text)
    return f"CWE-{int(m.group(1))}" if m else ""


def _retrieved_cwes(item_dir: Path) -> set[str]:
    ids: set[str] = set()
    for path in sorted(item_dir.glob("bm25_response_*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        preds = data.get("predictions") if isinstance(data, dict) else None
        if not isinstance(preds, list):
            continue
        for pred in preds:
            if not isinstance(pred, dict):
                continue
            rules = pred.get("top_sast_rules")
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if isinstance(rule, dict):
                    cid = _normalise_cwe(rule.get("cwe_id") or rule.get("cwe"))
                    if cid:
                        ids.add(cid)
    return ids


class Stage3Hypotheses(Stage):
    name = "stage3_hypotheses"

    def __init__(self, config: Config, client: ChatClient, logger: RunLogger):
        self.config = config
        self.client = client
        self._logger = logger
        self.bm25: BM25Retriever | None = None

    def execute(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        stage_dir = self._logger.stage_dir(self.name)
        self._logger.write_json(stage_dir / "input.json", candidates)
        results: list[dict[str, Any]] = []
        if not candidates:
            self._logger.write_json(stage_dir / "output.json", results)
            return results

        self.bm25 = BM25Retriever(self.config.bm25, self._logger)
        system = prompt("stage3_hypotheses.md").replace("__MAX_HYPOTHESES__", str(self.config.pipeline.max_hypotheses))

        for candidate in candidates:
            cid = str(candidate["candidate_id"])
            item_dir = stage_dir / cid
            item_dir.mkdir(parents=True, exist_ok=True)

            # Fail-closed retrieval contract: every candidate gets at least one
            # deterministic BM25 query even if the LLM tries to skip the tool.
            initial = self.bm25.search(candidate, self.config.bm25.top_k)
            self._logger.write_json(item_dir / "bm25_response_1.json", initial)

            bm25_tool = make_bm25_tool(
                self.bm25,
                candidate,
                item_dir,
                self.config.bm25.max_requests_per_candidate,
                initial_count=1,
            )
            agent = AgentRunner(
                self.client,
                ToolRegistry([bm25_tool]),
                self._logger,
                stage=f"{self.name}:{cid}",
                max_steps=self.config.agents.stage3_max_steps,
                artifact_dir=item_dir,
            )
            initial_rules = compact_rules(initial)
            user_prompt = (
                "STAGE-2 CANDIDATE:\n" + json.dumps(candidate, ensure_ascii=False, indent=2)
                + "\n\nINITIAL BM25 RULES (request #1, already executed by the program):\n"
                + json.dumps(initial_rules, ensure_ascii=False, indent=2)
            )
            answer = agent.run(system, user_prompt)
            if isinstance(answer, dict) and isinstance(answer.get("hypotheses"), list):
                raw_hypotheses = answer["hypotheses"]
            elif isinstance(answer, list):
                raw_hypotheses = answer
            else:
                raise ValueError(f"Stage 3 {cid} final answer must contain a hypotheses array")

            allowed = _retrieved_cwes(item_dir)
            if not allowed:
                self._logger.event("stage3_no_retrieved_cwe", {"candidate_id": cid})
            hypotheses: list[dict[str, Any]] = []
            seen: set[str] = set()
            for h in raw_hypotheses:
                if not isinstance(h, dict):
                    continue
                cwe = _normalise_cwe(h.get("cwe_id"))
                if not cwe or cwe not in allowed or cwe in seen:
                    continue
                reason = str(h.get("fit_reason") or "").strip()
                if not reason:
                    continue
                hypotheses.append({
                    "cwe_id": cwe,
                    "cwe_name": str(h.get("cwe_name") or ""),
                    "fit_reason": reason,
                    "proposal_source": "adaptive_bm25",
                    "retrieved_by_sast": True,
                })
                seen.add(cwe)
                if len(hypotheses) >= self.config.pipeline.max_hypotheses:
                    break

            if raw_hypotheses and not hypotheses:
                raise ValueError(f"Stage 3 {cid} returned hypotheses but none passed the retrieved-CWE contract")
            self._logger.event("hypothesis_validation", {"candidate_id": cid, "proposed": len(raw_hypotheses), "retained": len(hypotheses)})
            output = dict(candidate)
            output["hypotheses"] = hypotheses
            output["retrieved_cwe_ids"] = sorted(allowed)
            results.append(output)
            self._logger.write_json(item_dir / "output.json", output)

        self._logger.write_json(stage_dir / "output.json", results)
        return results
