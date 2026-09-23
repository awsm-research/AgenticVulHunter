"""Stage 3: generate vulnerability hypotheses with focused CWE retrieval.

BM25 retrieves relevant security rules from rules.json and the agent uses that
evidence to form a small set of CWE hypotheses for each candidate.
"""

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
    match = re.search(r"(?:CWE[-_ ]?)?(\d+)", text)
    return f"CWE-{int(match.group(1))}" if match else ""


def _retrieved_cwes(item_dir: Path) -> set[str]:
    ids: set[str] = set()
    for path in sorted(item_dir.glob("bm25_response_*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        predictions = data.get("predictions") if isinstance(data, dict) else None
        if not isinstance(predictions, list):
            continue
        for prediction in predictions:
            if not isinstance(prediction, dict):
                continue
            rules = prediction.get("top_sast_rules")
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if isinstance(rule, dict):
                    cwe = _normalise_cwe(rule.get("cwe_id") or rule.get("cwe"))
                    if cwe:
                        ids.add(cwe)
    return ids


class Stage3Hypotheses(Stage):
    name = "stage3_hypotheses"

    def __init__(self, config: Config, client: ChatClient, logger: RunLogger):
        self.config = config
        self.client = client
        self.logger = logger
        self.bm25 = BM25Retriever(config.bm25, logger)

    def execute(self, value: Any) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = value
        stage_dir = self.logger.stage_dir(self.name)
        self.logger.write_json(stage_dir / "input.json", candidates)
        results: list[dict[str, Any]] = []
        if not candidates:
            self.logger.write_json(stage_dir / "output.json", results)
            return results

        system = prompt("stage3_hypotheses.md").replace(
            "__MAX_HYPOTHESES__", str(self.config.pipeline.max_hypotheses)
        )

        for candidate in candidates:
            candidate_id = str(candidate["candidate_id"])
            item_dir = stage_dir / candidate_id
            item_dir.mkdir(parents=True, exist_ok=True)

            initial = self.bm25.search(candidate, self.config.bm25.top_k)
            self.logger.write_json(item_dir / "bm25_response_1.json", initial)
            initial_rules = compact_rules(initial)

            tool = make_bm25_tool(
                self.bm25,
                candidate,
                item_dir,
                self.config.bm25.max_requests_per_candidate,
                initial_count=1,
            )
            agent = AgentRunner(
                self.client,
                ToolRegistry([tool]),
                self.logger,
                stage=f"{self.name}:{candidate_id}",
                max_steps=self.config.agents.stage3_max_steps,
                artifact_dir=item_dir,
            )

            user_prompt = (
                "STAGE-2 CANDIDATE:\n"
                + json.dumps(candidate, ensure_ascii=False, indent=2)
                + "\n\nINITIAL BM25 RULES:\n"
                + json.dumps(initial_rules, ensure_ascii=False, indent=2)
            )

            try:
                answer = agent.run(system, user_prompt)
            except InvalidJSONActionsExhausted as exc:
                allowed = _retrieved_cwes(item_dir)
                output = dict(candidate)
                output["hypotheses"] = []
                output["retrieved_cwe_ids"] = sorted(allowed)
                output["stage3_status"] = "model_output_error"
                self.logger.write_json(
                    item_dir / "model_output_error.json",
                    {
                        "candidate_id": candidate_id,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                results.append(output)
                self.logger.write_json(item_dir / "output.json", output)
                continue

            if isinstance(answer, dict) and isinstance(answer.get("hypotheses"), list):
                raw_hypotheses = answer["hypotheses"]
            elif isinstance(answer, list):
                raw_hypotheses = answer
            else:
                raise ValueError(
                    f"Stage 3 {candidate_id} final answer must contain a hypotheses array"
                )

            allowed = _retrieved_cwes(item_dir)
            hypotheses: list[dict[str, Any]] = []
            seen: set[str] = set()
            for hypothesis in raw_hypotheses:
                if not isinstance(hypothesis, dict):
                    continue
                cwe = _normalise_cwe(hypothesis.get("cwe_id"))
                reason = str(hypothesis.get("fit_reason") or "").strip()
                if not cwe or cwe not in allowed or cwe in seen or not reason:
                    continue

                hypotheses.append(
                    {
                        "cwe_id": cwe,
                        "cwe_name": str(hypothesis.get("cwe_name") or ""),
                        "fit_reason": reason,
                        "proposal_source": "adaptive_bm25",
                        "retrieved_by_sast": True,
                    }
                )
                seen.add(cwe)
                if len(hypotheses) >= self.config.pipeline.max_hypotheses:
                    break

            if raw_hypotheses and not hypotheses:
                raise ValueError(
                    f"Stage 3 {candidate_id} returned no hypothesis supported by BM25 retrieval"
                )

            output = dict(candidate)
            output["hypotheses"] = hypotheses
            output["retrieved_cwe_ids"] = sorted(allowed)
            results.append(output)
            self.logger.write_json(item_dir / "output.json", output)

        self.logger.write_json(stage_dir / "output.json", results)
        return results
