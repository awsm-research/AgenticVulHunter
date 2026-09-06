"""Deterministic application judge policy (distinct from benchmark mean-only).

Raw score = mean of the five evidence categories. Application relationship and
contradiction caps are retained from v0.5.0. See docs/research.md before using
application scores to reproduce benchmark results.
"""
from __future__ import annotations
from typing import Any

_SCORE_KEYS = (
    "exact_cwe_mechanism",
    "connection",
    "diff_causality",
    "security_control",
    "concrete_impact",
)

_RELATIONSHIP_CAPS = {
    "exact": 1.00,
    "family_compatible": 0.79,
    "partial": 0.59,
    "mismatch": 0.29,
}

_CONTRADICTION_CAPS = {
    "none": 1.00,
    "minor": 0.89,
    "material": 0.69,
    "fatal": 0.29,
}


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


def verdict(score: float, threshold: float, relationship: str, contradiction: str) -> str:
    if relationship == "mismatch" or contradiction == "fatal":
        return "rejected"
    if relationship in {"exact", "family_compatible"} and contradiction in {"none", "minor"} and score >= threshold:
        return "supported"
    if score >= 0.50:
        return "uncertain"
    return "rejected"


