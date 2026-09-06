from __future__ import annotations

import json
from typing import Any

from .base import Stage
from ..config import Config
from ..llm import AgentRunner, ChatClient, extract_json_value
from ..resources import cwe_knowledge, prompt
from ..runlog import RunLogger
from ..tools.repo import RepositoryTools


from .scoring import _RELATIONSHIP_CAPS, _CONTRADICTION_CAPS, raw_score as _raw_score, verdict as _verdict


def _canonical_cwe(cwe_id: str, supplied_name: str = "") -> dict[str, Any]:
    entry = cwe_knowledge().get(cwe_id, {})
    return {
        "cwe_id": cwe_id,
        "cwe_name": entry.get("name") or supplied_name,
        "description": entry.get("description") or "",
        "impact": entry.get("impact") or "",
        "patterns": entry.get("patterns") or [],
        "detection_indicators": entry.get("detection_indicators") or [],
        "remediation_steps": entry.get("remediation_steps") or [],
        "related_cwes": entry.get("related_cwes") or [],
    }


class Stage4Judge(Stage):
    name = "stage4_judge"

    def __init__(self, config: Config, client: ChatClient, logger: RunLogger, repo_tools: RepositoryTools):
        self.config = config
        self.client = client
        self._logger = logger
        self.repo_tools = repo_tools

    def _validate(self, candidate: dict[str, Any], hypothesis: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
        for field in ("candidate_id", "filepath", "changed_line", "statement"):
            if output.get(field) != candidate.get(field):
                raise ValueError(f"Stage 4 changed immutable field {field}")
        if "change_type" in output and output.get("change_type") != candidate.get("change_type"):
            raise ValueError("Stage 4 changed immutable field change_type")
        if str(output.get("cwe_id") or "").upper() != str(hypothesis.get("cwe_id") or "").upper():
            raise ValueError("Stage 4 changed target CWE")

        relationship = str(output.get("cwe_relationship") or "")
        if relationship not in _RELATIONSHIP_CAPS:
            raise ValueError("invalid cwe_relationship")
        severity = str(output.get("contradiction_severity") or "")
        if severity not in _CONTRADICTION_CAPS:
            raise ValueError("invalid contradiction_severity")

        raw_score = _raw_score(output)
        cap = min(_RELATIONSHIP_CAPS[relationship], _CONTRADICTION_CAPS[severity])
        score = min(raw_score, cap)
        final = dict(output)
        final["change_type"] = candidate.get("change_type", "A")
        final["raw_score"] = raw_score
        final["score_cap"] = cap
        final["score"] = score
        final["verdict"] = _verdict(
            score,
            self.config.pipeline.confidence_threshold,
            relationship,
            severity,
        )
        if final["verdict"] != "supported" and not str(final.get("review_comment") or "").strip():
            final["review_comment"] = ""
        return final

    def _api_judge(self, payload: dict[str, Any], candidate: dict[str, Any], hypothesis: dict[str, Any], item_dir) -> dict[str, Any]:
        system = prompt("stage4_judge.md")
        user = "PAIR INPUT:\n" + json.dumps(payload, ensure_ascii=False, indent=2)
        last_error: Exception | None = None
        for attempt in range(1, 3):
            retry = "" if last_error is None else f"\n\nPrevious output was invalid: {last_error}. Return one complete JSON object only."
            response = self.client.chat(
                [{"role": "system", "content": system}, {"role": "user", "content": user + retry}],
                metadata={"stage": self.name, "candidate_id": candidate["candidate_id"], "cwe_id": hypothesis["cwe_id"], "attempt": attempt, "mode": "api"},
            )
            (item_dir / f"attempt-{attempt}.txt").write_text(response.content, encoding="utf-8")
            try:
                raw = extract_json_value(response.content)
                if not isinstance(raw, dict):
                    raise ValueError("judge response must be a JSON object")
                return self._validate(candidate, hypothesis, raw)
            except Exception as exc:
                last_error = exc
        raise RuntimeError(f"Stage 4 API judge failed validation after 2 attempts: {last_error}")

    def _agentic_judge(self, payload: dict[str, Any], candidate: dict[str, Any], hypothesis: dict[str, Any], item_dir) -> dict[str, Any]:
        agent = AgentRunner(
            self.client,
            self.repo_tools.registry(include_list=False),
            self._logger,
            stage=f"{self.name}:{candidate['candidate_id']}:{hypothesis['cwe_id']}",
            max_steps=self.config.agents.stage4_max_steps,
            artifact_dir=item_dir,
        )
        answer = agent.run(
            prompt("stage4_judge.md") + "\n\nYou may use repository tools only to resolve a concrete unresolved fact. Do not relocate the candidate or substitute another CWE.",
            "PAIR INPUT:\n" + json.dumps(payload, ensure_ascii=False, indent=2),
        )
        if not isinstance(answer, dict):
            raise ValueError("Stage 4 agentic judge final answer must be a JSON object")
        return self._validate(candidate, hypothesis, answer)

    def execute(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        stage_dir = self._logger.stage_dir(self.name)
        self._logger.write_json(stage_dir / "input.json", candidates)
        results: list[dict[str, Any]] = []

        for candidate in candidates:
            cid = str(candidate["candidate_id"])
            assessments: list[dict[str, Any]] = []
            for hypothesis in candidate.get("hypotheses", []):
                if not isinstance(hypothesis, dict):
                    continue
                cwe_id = str(hypothesis.get("cwe_id") or "")
                item_dir = stage_dir / cid / cwe_id
                item_dir.mkdir(parents=True, exist_ok=True)
                cwe = _canonical_cwe(cwe_id, str(hypothesis.get("cwe_name") or ""))
                payload = {
                    "candidate": {k: v for k, v in candidate.items() if k not in {"hypotheses", "retrieved_cwe_ids"}},
                    "target_cwe": cwe,
                    "stage3_hypothesis": hypothesis,
                }
                self._logger.write_json(item_dir / "input.json", payload)
                if self.config.agents.stage4_mode == "agentic":
                    assessment = self._agentic_judge(payload, candidate, hypothesis, item_dir)
                else:
                    assessment = self._api_judge(payload, candidate, hypothesis, item_dir)
                assessments.append(assessment)
                self._logger.write_json(item_dir / "assessment.json", assessment)

            finding = dict(candidate)
            finding["cwe_assessments"] = assessments
            results.append(finding)
            self._logger.write_json(stage_dir / cid / "output.json", finding)

        self._logger.write_json(stage_dir / "output.json", results)
        return results
