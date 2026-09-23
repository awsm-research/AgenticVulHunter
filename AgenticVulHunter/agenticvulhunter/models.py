from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Candidate:
    candidate_id: str
    filepath: str
    changed_line: int
    statement: str
    change_type: str = "A"
    function_name: str = ""
    operation_type: str = ""
    selection_reason: str = ""
    security_relevance_score: float = 0.0
    code_context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Hypothesis:
    cwe_id: str
    cwe_name: str = ""
    fit_reason: str = ""
    proposal_source: str = "adaptive_bm25"
    retrieved_by_sast: bool = True
    retrieval_context: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    candidate_id: str
    filepath: str
    changed_line: int
    statement: str
    cwe_id: str
    cwe_name: str
    final_score: float
    review_comment: str
    assessment: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StageResult:
    name: str
    output: Any
    duration_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineResult:
    run_id: str
    status: str
    findings: list[Finding]
    comments: list[dict[str, Any]]
    run_dir: str
    stages: list[StageResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "comments": self.comments,
            "run_dir": self.run_dir,
            "stages": [asdict(s) for s in self.stages],
        }
