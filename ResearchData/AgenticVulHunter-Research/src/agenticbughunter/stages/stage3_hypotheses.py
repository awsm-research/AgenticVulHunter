from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import Config
from ..llm import AgentRunner, ChatClient, InvalidJSONActionsExhausted, ToolRegistry
from ..resources import prompt
from ..runlog import RunLogger
from ..tools.bm25 import BM25Retriever, compact_rules, make_bm25_tool
from .base import Stage


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

    def execute(self, value: Any) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = value
        stage_dir = self._logger.stage_dir(self.name)
        self._logger.write_json(stage_dir / "input.json", candidates)
        results: list[dict[str, Any]] = []
        if not candidates:
            self._logger.write_json(stage_dir / "output.json", results)
            return results

        retrieval_enabled = self.config.bm25.enabled
        if retrieval_enabled:
            self.bm25 = BM25Retriever(self.config.bm25, self._logger)
        system = prompt(
            "stage3_hypotheses.md"
            if retrieval_enabled
            else "stage3_hypotheses_no_bm25.md"
        ).replace("__MAX_HYPOTHESES__", str(self.config.pipeline.max_hypotheses))

        for candidate in candidates:
            cid = str(candidate["candidate_id"])
            item_dir = stage_dir / cid
            item_dir.mkdir(parents=True, exist_ok=True)

            tools = []
            initial_rules: list[dict[str, Any]] = []
            if retrieval_enabled:
                assert self.bm25 is not None
                # Fail-closed retrieval contract: every candidate gets at least one
                # deterministic BM25 query even if the LLM tries to skip the tool.
                initial = self.bm25.search(candidate, self.config.bm25.top_k)
                self._logger.write_json(item_dir / "bm25_response_1.json", initial)
                initial_rules = compact_rules(initial)
                tools.append(
                    make_bm25_tool(
                        self.bm25,
                        candidate,
                        item_dir,
                        self.config.bm25.max_requests_per_candidate,
                        initial_count=1,
                    )
                )
            agent = AgentRunner(
                self.client,
                ToolRegistry(tools),
                self._logger,
                stage=f"{self.name}:{cid}",
                max_steps=self.config.agents.stage3_max_steps,
                artifact_dir=item_dir,
            )
            evidence_label = (
                "STAGE-2 CANDIDATE"
                if retrieval_enabled
                else "FULL STAGE-2 EVIDENCE FOR MODEL-ONLY CWE PROPOSAL"
            )
            user_prompt = (
                evidence_label
                + ":\n"
                + json.dumps(candidate, ensure_ascii=False, indent=2)
            )
            if retrieval_enabled:
                user_prompt += (
                    "\n\nINITIAL BM25 RULES (request #1, already executed by the program):\n"
                    + json.dumps(initial_rules, ensure_ascii=False, indent=2)
                )
            try:
                answer = agent.run(system, user_prompt)
            except InvalidJSONActionsExhausted as exc:
                allowed = _retrieved_cwes(item_dir) if retrieval_enabled else set()
                error = {
                    "candidate_id": cid,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "recovery": "candidate_skipped_with_no_hypotheses",
                    "retrieved_cwe_ids": sorted(allowed),
                }
                self._logger.write_json(item_dir / "model_output_error.json", error)
                self._logger.event("stage3_candidate_degraded", error)
                output = dict(candidate)
                output["hypotheses"] = []
                output["retrieved_cwe_ids"] = sorted(allowed)
                output["stage3_status"] = "model_output_error"
                results.append(output)
                self._logger.write_json(item_dir / "output.json", output)
                continue
            if isinstance(answer, dict) and isinstance(answer.get("hypotheses"), list):
                raw_hypotheses = answer["hypotheses"]
            elif isinstance(answer, list):
                raw_hypotheses = answer
            else:
                raise ValueError(
                    f"Stage 3 {cid} final answer must contain a hypotheses array"
                )

            allowed = _retrieved_cwes(item_dir) if retrieval_enabled else set()
            if retrieval_enabled and not allowed:
                self._logger.event("stage3_no_retrieved_cwe", {"candidate_id": cid})
            hypotheses: list[dict[str, Any]] = []
            seen: set[str] = set()
            for h in raw_hypotheses:
                if not isinstance(h, dict):
                    continue
                cwe = _normalise_cwe(h.get("cwe_id"))
                if not cwe or (retrieval_enabled and cwe not in allowed) or cwe in seen:
                    continue
                reason = str(h.get("fit_reason") or "").strip()
                if not reason:
                    continue
                hypotheses.append(
                    {
                        "cwe_id": cwe,
                        "cwe_name": str(h.get("cwe_name") or ""),
                        "fit_reason": reason,
                        "proposal_source": (
                            "adaptive_bm25" if retrieval_enabled else "model_only"
                        ),
                        "retrieved_by_sast": retrieval_enabled,
                    }
                )
                seen.add(cwe)
                # Retrieval-backed runs retain their configured experimental cap.
                # The model-only ablation intentionally has no numeric hypothesis
                # target or cap: it keeps every distinct, evidence-supported CWE
                # returned by the model.
                if (
                    retrieval_enabled
                    and len(hypotheses) >= self.config.pipeline.max_hypotheses
                ):
                    break

            if raw_hypotheses and not hypotheses:
                raise ValueError(
                    f"Stage 3 {cid} returned hypotheses but none passed the retrieved-CWE contract"
                )
            self._logger.event(
                "hypothesis_validation",
                {
                    "candidate_id": cid,
                    "proposed": len(raw_hypotheses),
                    "retained": len(hypotheses),
                },
            )
            output = dict(candidate)
            output["hypotheses"] = hypotheses
            output["retrieved_cwe_ids"] = sorted(allowed)
            output["stage3_retrieval_mode"] = (
                "adaptive_bm25" if retrieval_enabled else "disabled_model_only"
            )
            results.append(output)
            self._logger.write_json(item_dir / "output.json", output)

        self._logger.write_json(stage_dir / "output.json", results)
        return results
