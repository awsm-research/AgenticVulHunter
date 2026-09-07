"""Deterministic five-category scoring used by the research workflow."""

from __future__ import annotations

from typing import Any

_SCORE_KEYS = (
    "exact_cwe_mechanism",
    "connection",
    "diff_causality",
    "security_control",
    "concrete_impact",
)

CWE_RELATIONSHIPS = frozenset({"exact", "family_compatible", "partial", "mismatch"})
CONTRADICTION_SEVERITIES = frozenset({"none", "minor", "material", "fatal"})


def raw_score(output: dict[str, Any]) -> float:
    categories = output.get("category_scores")
    if not isinstance(categories, dict):
        raise ValueError("category_scores must be an object")
    values: list[float] = []
    for key in _SCORE_KEYS:
        item = categories.get(key)
        if not isinstance(item, dict):
            raise ValueError(f"missing category_scores.{key}")
        if isinstance(item.get("score"), bool):
            raise ValueError(f"score for {key} must be numeric, not boolean")
        try:
            value = float(item.get("score"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid score for {key}") from exc
        if not 0 <= value <= 1:
            raise ValueError(f"score for {key} must be in [0,1]")
        values.append(value)
    return sum(values) / len(values)


def verdict(score: float, threshold: float) -> str:
    if score >= threshold:
        return "supported"
    if score >= 0.50:
        return "uncertain"
    return "rejected"
