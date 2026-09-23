"""Stage 4: validate each vulnerability hypothesis and assign a final score.

This is the final reasoning stage. The CLI threshold is applied after this
stage, so filtering is not implemented as a separate Stage 5.
"""

from __future__ import annotations

import json
from typing import Any

from ..config import Config
from ..llm import ChatClient, extract_json_value
from ..resources import cwe_knowledge, prompt
from ..runlog import RunLogger
from .base import Stage
from .scoring import (
    CONTRADICTION_SEVERITIES,
    CWE_RELATIONSHIPS,
)
from .scoring import raw_score as _raw_score


def validate_security_control_evidence(output: dict[str, Any]) -> None:
    """Require structured proof before a control deficiency can score highly."""
    category = (output.get("category_scores") or {}).get("security_control") or {}
    try:
        score = float(category.get("score"))
    except (TypeError, ValueError) as exc:
        raise ValueError("security_control score must be numeric") from exc
    required = str(category.get("required_control") or "").strip()
    requirement = str(category.get("control_requirement_evidence") or "").strip()
    deficiency = str(category.get("deficiency_evidence") or "").strip()
    checked = category.get("existing_controls_checked")
    if not isinstance(checked, list) or not all(
        isinstance(item, str) for item in checked
    ):
        raise ValueError(
            "security_control existing_controls_checked must be a string array"
        )
    if score >= 0.61 and not (required and requirement and deficiency and checked):
        raise ValueError(
            "a security_control score above 0.60 requires required_control, "
            "control_requirement_evidence, existing_controls_checked, and "
            "deficiency_evidence grounded in the demonstrated path"
        )


def validate_supported_evidence(output: dict[str, Any], score: float) -> None:
    """Prevent unresolved essential facts from being promoted to a finding."""
    if score < 0.80:
        return
    uncertainty = " ".join(str(item) for item in output.get("unresolved_facts") or [])
    review = str(output.get("review_comment") or "")
    conditional = (" if " in f" {review.lower()} ") or "depends on" in review.lower()
    essential_terms = (
        "downstream",
        "attacker control",
        "authorization",
        "authentication",
        "reachability",
        "exploitability",
        "concrete impact",
    )
    if any(term in uncertainty.lower() for term in essential_terms):
        raise ValueError(
            "supported score conflicts with an unresolved essential mechanism, "
            "control, reachability, or impact fact"
        )
    if conditional:
        raise ValueError(
            "supported review_comment must describe demonstrated impact, not an "
            "impact conditional on unknown downstream behavior"
        )


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

    def __init__(
        self,
        config: Config,
        client: ChatClient,
        logger: RunLogger,
    ):
        self.config = config
        self.client = client
        self._logger = logger

    def _validate(
        self,
        candidate: dict[str, Any],
        hypothesis: dict[str, Any],
        output: dict[str, Any],
    ) -> dict[str, Any]:
        for field in ("candidate_id", "filepath", "changed_line", "statement"):
            if output.get(field) != candidate.get(field):
                raise ValueError(f"Stage 4 changed immutable field {field}")
        if "change_type" in output and output.get("change_type") != candidate.get(
            "change_type"
        ):
            raise ValueError("Stage 4 changed immutable field change_type")
        if (
            str(output.get("cwe_id") or "").upper()
            != str(hypothesis.get("cwe_id") or "").upper()
        ):
            raise ValueError("Stage 4 changed target CWE")

        relationship = str(output.get("cwe_relationship") or "")
        if relationship not in CWE_RELATIONSHIPS:
            raise ValueError("invalid cwe_relationship")
        severity = str(output.get("contradiction_severity") or "")
        if severity not in CONTRADICTION_SEVERITIES:
            raise ValueError("invalid contradiction_severity")

        validate_security_control_evidence(output)

        score = _raw_score(output)
        validate_supported_evidence(output, score)
        final = dict(output)
        final["change_type"] = candidate.get("change_type", "A")
        final["raw_score"] = score
        final["score"] = score
        return final

    def _api_judge(
        self,
        payload: dict[str, Any],
        candidate: dict[str, Any],
        hypothesis: dict[str, Any],
        item_dir,
    ) -> dict[str, Any]:
        system = prompt("stage4_judge.md")
        user = "PAIR INPUT:\n" + json.dumps(payload, ensure_ascii=False, indent=2)
        last_error: Exception | None = None
        for attempt in range(1, 3):
            retry = (
                ""
                if last_error is None
                else f"\n\nPrevious output was invalid: {last_error}. Return one complete JSON object only."
            )
            response = self.client.chat(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user + retry},
                ],
                metadata={
                    "stage": self.name,
                    "candidate_id": candidate["candidate_id"],
                    "cwe_id": hypothesis["cwe_id"],
                    "attempt": attempt,
                    "mode": "api",
                },
            )
            (item_dir / f"attempt-{attempt}.txt").write_text(
                response.content, encoding="utf-8"
            )
            try:
                raw = extract_json_value(response.content)
                if not isinstance(raw, dict):
                    raise ValueError("judge response must be a JSON object")
                return self._validate(candidate, hypothesis, raw)
            except Exception as exc:
                last_error = exc
        raise RuntimeError(
            f"Stage 4 API judge failed validation after 2 attempts: {last_error}"
        )

    def execute(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        stage_dir = self._logger.stage_dir(self.name)
        self._logger.write_json(stage_dir / "input.json", candidates)
        results: list[dict[str, Any]] = []

        for candidate in candidates:
            cid = str(candidate["candidate_id"])
            assessments: list[dict[str, Any]] = []
            assessment_errors: list[dict[str, Any]] = []
            for hypothesis in candidate.get("hypotheses", []):
                if not isinstance(hypothesis, dict):
                    continue
                cwe_id = str(hypothesis.get("cwe_id") or "")
                item_dir = stage_dir / cid / cwe_id
                item_dir.mkdir(parents=True, exist_ok=True)
                cwe = _canonical_cwe(cwe_id, str(hypothesis.get("cwe_name") or ""))
                payload = {
                    "candidate": {
                        k: v
                        for k, v in candidate.items()
                        if k not in {"hypotheses", "retrieved_cwe_ids"}
                    },
                    "target_cwe": cwe,
                    "stage3_hypothesis": hypothesis,
                }
                self._logger.write_json(item_dir / "input.json", payload)
                try:
                    assessment = self._api_judge(
                        payload, candidate, hypothesis, item_dir
                    )
                except Exception as exc:
                    error = {
                        "candidate_id": cid,
                        "cwe_id": cwe_id,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "recovery": "assessment_skipped_with_no_finding",
                    }
                    assessment_errors.append(error)
                    self._logger.write_json(item_dir / "model_output_error.json", error)
                    self._logger.event("stage4_candidate_degraded", error)
                    continue
                assessments.append(assessment)
                self._logger.write_json(item_dir / "assessment.json", assessment)

            finding = dict(candidate)
            finding["cwe_assessments"] = assessments
            finding["stage4_status"] = "degraded" if assessment_errors else "completed"
            if assessment_errors:
                finding["stage4_errors"] = assessment_errors
            results.append(finding)
            self._logger.write_json(stage_dir / cid / "output.json", finding)

        self._logger.write_json(stage_dir / "output.json", results)
        return results
