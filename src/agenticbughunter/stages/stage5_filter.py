from __future__ import annotations

from typing import Any

from ..config import Config
from ..models import Finding
from ..runlog import RunLogger
from .base import Stage


class Stage5Filter(Stage):
    name = "stage5_filter"

    def __init__(self, config: Config, logger: RunLogger):
        self.config = config
        self._logger = logger

    def execute(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        stage_dir = self._logger.stage_dir(self.name)
        self._logger.write_json(stage_dir / "input.json", findings)
        accepted: list[Finding] = []

        for finding in findings:
            assessments = finding.get("cwe_assessments")
            if not isinstance(assessments, list):
                continue
            eligible: list[dict[str, Any]] = []
            for assessment in assessments:
                if not isinstance(assessment, dict):
                    continue
                try:
                    score = float(assessment.get("score", 0.0))
                except (TypeError, ValueError):
                    continue
                if (
                    score >= self.config.pipeline.confidence_threshold
                    and str(assessment.get("verdict") or "") == "supported"
                    and bool(str(assessment.get("review_comment") or "").strip())
                ):
                    eligible.append(assessment)
            eligible.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
            if not eligible:
                continue
            best = eligible[0]
            accepted.append(
                Finding(
                    candidate_id=str(finding.get("candidate_id") or ""),
                    filepath=str(finding.get("filepath") or ""),
                    changed_line=int(finding.get("changed_line") or 0),
                    statement=str(finding.get("statement") or ""),
                    cwe_id=str(best.get("cwe_id") or ""),
                    cwe_name=str(best.get("cwe_name") or ""),
                    final_score=float(best.get("score", 0.0)),
                    verdict="supported",
                    review_comment=str(best.get("review_comment") or ""),
                    assessment=best,
                )
            )

        accepted.sort(key=lambda x: x.final_score, reverse=True)
        comments = [
            {
                "filepath": f.filepath,
                "line_number": f.changed_line,
                "change_type": str(f.assessment.get("change_type") or "A"),
                "review_comment": f.review_comment,
                "line_snippet": f.statement,
                "vuln_type": [f.cwe_id],
                "judge_final_score": f.final_score,
            }
            for f in accepted
        ]
        output = {
            "findings": [f.to_dict() for f in accepted],
            "comments": comments,
            "threshold": self.config.pipeline.confidence_threshold,
        }
        self._logger.write_json(stage_dir / "output.json", output)
        self._logger.write_json(self._logger.run_dir / "comments.json", comments)
        return output
