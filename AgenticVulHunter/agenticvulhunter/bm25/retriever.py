"""Lightweight BM25 retriever used during CWE hypothesis.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

RULES_FILE = Path(__file__).resolve().parent / "rules.json"

# Fixed research settings. These are not user configuration.
BM25_K1 = 1.5
BM25_B = 0.75
MAX_DF_RATIO = 0.25

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
    ".cs": "csharp",
}


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(as_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(as_text(v) for v in value)
    return str(value)


def normalize_cwe(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    match = re.search(r"CWE[-_ ]?(\d+)", text)
    if match:
        return f"CWE-{match.group(1)}"
    if text.isdigit():
        return f"CWE-{text}"
    return text


def split_identifier(token: str) -> list[str]:
    pieces = re.split(r"[._/\-]+", token)
    result: list[str] = []
    for piece in pieces:
        if not piece:
            continue
        expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", piece)
        expanded = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", expanded)
        result.extend(part for part in expanded.lower().split() if len(part) >= 2)
    return result


def tokenize(value: str) -> list[str]:
    raw_tokens = re.findall(
        r"[A-Za-z_][A-Za-z0-9_./-]*|CWE[-_ ]?\d+|\d+",
        str(value or ""),
    )
    tokens: list[str] = []
    for raw_token in raw_tokens:
        cwe = normalize_cwe(raw_token)
        if cwe.startswith("CWE-"):
            tokens.append(cwe.lower())
        else:
            tokens.append(raw_token.lower())
            tokens.extend(split_identifier(raw_token))
    return tokens


def item_to_text(item: dict[str, Any]) -> str:
    fields = (
        "operation_type",
        "selection_reason",
        "source_summary",
        "sink_summary",
        "guard_summary",
        "risk_pattern",
        "used_variable_sources",
        "called_apis",
        "called_function_context",
        "enclosing_conditions",
        "context_summary",
        "statement",
        "retrieval_query",
    )
    return " ".join(
        text
        for field in fields
        if (text := as_text(item.get(field)).strip())
    )


def rule_to_text(rule: dict[str, Any]) -> str:
    """Build the BM25 document directly from one rule."""
    fields = (
        "cwe_id",
        "cwe_name",
        "description",
        "rule_id",
        "language",
        "pattern",
        "severity",
        "remediation",
        "tags",
    )
    return " ".join(
        text
        for field in fields
        if (text := as_text(rule.get(field)).strip())
    )


def item_language(item: dict[str, Any]) -> str:
    language = str(item.get("language") or "").strip().lower()
    if language:
        return language
    filepath = str(item.get("filepath") or item.get("file") or "")
    return EXTENSION_TO_LANGUAGE.get(Path(filepath).suffix.lower(), "")


def normalize_language(language: str) -> str:
    aliases = {"py": "python", "js": "javascript", "ts": "typescript", "cs": "csharp"}
    value = str(language or "").strip().lower()
    return aliases.get(value, value)


def languages_compatible(candidate_language: str, rule_language: str) -> bool:
    candidate = normalize_language(candidate_language)
    rule = normalize_language(rule_language)
    return not candidate or not rule or rule == "generic" or candidate == rule


class BM25:
    def __init__(self, documents: list[str]):
        self.doc_tokens = [tokenize(document) for document in documents]
        self.doc_lengths = [len(tokens) for tokens in self.doc_tokens]
        self.avg_doc_length = (
            sum(self.doc_lengths) / len(self.doc_lengths) if self.doc_lengths else 0.0
        )
        self.term_freqs = [Counter(tokens) for tokens in self.doc_tokens]
        self.doc_freq: Counter[str] = Counter()
        for counts in self.term_freqs:
            for token in counts:
                self.doc_freq[token] += 1
        self.num_docs = len(self.doc_tokens)

    def idf(self, token: str) -> float:
        df = self.doc_freq.get(token, 0)
        return math.log(1 + (self.num_docs - df + 0.5) / (df + 0.5))

    def score_document(self, query_tokens: list[str], index: int) -> float:
        if self.num_docs == 0 or self.avg_doc_length == 0:
            return 0.0
        doc_length = self.doc_lengths[index]
        if doc_length == 0:
            return 0.0

        counts = self.term_freqs[index]
        score = 0.0
        for token in set(query_tokens):
            tf = counts.get(token, 0)
            if tf == 0:
                continue
            if self.doc_freq.get(token, 0) / self.num_docs > MAX_DF_RATIO:
                continue
            numerator = tf * (BM25_K1 + 1)
            denominator = tf + BM25_K1 * (
                1 - BM25_B + BM25_B * doc_length / self.avg_doc_length
            )
            score += self.idf(token) * numerator / denominator
        return score

    def score(self, query_tokens: list[str]) -> list[float]:
        return [self.score_document(query_tokens, i) for i in range(self.num_docs)]


class SASTRetriever:
    """Small in-process BM25 retriever using only the bundled rules file."""

    def __init__(self, rules_file: str | Path = RULES_FILE):
        self.rules_file = Path(rules_file)
        self.rules = json.loads(self.rules_file.read_text(encoding="utf-8"))
        if not isinstance(self.rules, list):
            raise ValueError("rules.json must contain a JSON array")
        self.cwe_count = len(
            {str(rule.get("cwe_id") or "") for rule in self.rules if isinstance(rule, dict)}
        )

    def rank(self, item: dict[str, Any], top_k: int = 5) -> list[dict[str, Any]]:
        query_tokens = tokenize(item_to_text(item))
        if not query_tokens:
            return []

        candidate_language = item_language(item)
        applicable_rules = [
            rule
            for rule in self.rules
            if isinstance(rule, dict)
            and languages_compatible(candidate_language, str(rule.get("language") or ""))
        ]
        if not applicable_rules:
            return []

        documents = [rule_to_text(rule) for rule in applicable_rules]
        scores = BM25(documents).score(query_tokens)

        best_by_cwe: dict[str, tuple[float, dict[str, Any]]] = {}
        for rule, raw_score in zip(applicable_rules, scores):
            score = float(raw_score)
            if score <= 0:
                continue
            cwe_id = str(rule.get("cwe_id") or "UNKNOWN")
            current = best_by_cwe.get(cwe_id)
            if current is None or score > current[0]:
                best_by_cwe[cwe_id] = (score, rule)

        ranked = sorted(best_by_cwe.values(), key=lambda row: row[0], reverse=True)[:top_k]
        results: list[dict[str, Any]] = []
        for rank, (score, rule) in enumerate(ranked, start=1):
            results.append(
                {
                    "rank": rank,
                    "rule_id": rule.get("rule_id"),
                    "cwe_id": rule.get("cwe_id"),
                    "cwe_name": rule.get("cwe_name"),
                    "language": rule.get("language"),
                    "severity": rule.get("severity"),
                    "sast_tool": rule.get("sast_tool"),
                    "is_fallback": str(rule.get("sast_tool") or "").lower() == "cwe-fallback",
                    "score": round(score, 4),
                    "raw_bm25_score": round(score, 4),
                    "description": rule.get("description"),
                    "pattern": rule.get("pattern"),
                    "remediation": rule.get("remediation"),
                    "tags": rule.get("tags"),
                    "untrusted_hypothesis": True,
                }
            )
        return results


def model_exists(rules_file: str | Path = RULES_FILE) -> bool:
    path = Path(rules_file)
    if not path.is_file():
        return False
    try:
        return isinstance(json.loads(path.read_text(encoding="utf-8")), list)
    except Exception:
        return False
