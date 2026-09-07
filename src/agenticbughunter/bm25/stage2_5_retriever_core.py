from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parent
FILES_DIR = PROJECT_DIR / "files"
DEFAULT_MODEL_DIR = FILES_DIR / "stage2_5_model"

DEFAULT_BM25_K1 = 1.5
DEFAULT_BM25_B = 0.75
DEFAULT_MAX_DF_RATIO = 0.25


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
        for part in expanded.lower().split():
            if len(part) >= 2:
                result.append(part)
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
            continue
        tokens.append(raw_token.lower())
        tokens.extend(split_identifier(raw_token))
    return tokens


def item_to_text(item: dict[str, Any]) -> str:
    fields = [
        item.get("operation_type"),
        item.get("selection_reason"),
        item.get("source_summary"),
        item.get("sink_summary"),
        item.get("guard_summary"),
        item.get("risk_pattern"),
        item.get("used_variable_sources"),
        item.get("called_apis"),
        item.get("called_function_context"),
        item.get("enclosing_conditions"),
        item.get("context_summary"),
        item.get("statement"),
        # Stage 3 agent-generated refinement
        item.get("retrieval_query"),
    ]

    parts: list[str] = []

    for value in fields:
        text = as_text(value).strip()

        if text:
            parts.append(text)

    return " ".join(parts)


def item_language(item: dict[str, Any]) -> str:
    language = str(item.get("language") or "").strip().lower()
    if language:
        return language
    filepath = str(item.get("filepath") or item.get("file") or "")
    return EXTENSION_TO_LANGUAGE.get(Path(filepath).suffix.lower(), "")


def normalize_language(language: str) -> str:
    aliases = {
        "py": "python",
        "js": "javascript",
        "ts": "typescript",
        "cs": "csharp",
    }
    value = str(language or "").strip().lower()
    return aliases.get(value, value)


def languages_compatible(candidate_language: str, rule_language: str) -> bool:
    candidate = normalize_language(candidate_language)
    rule = normalize_language(rule_language)
    if not candidate or not rule:
        return True
    if rule == "generic":
        return True
    return candidate == rule


class BM25:
    def __init__(
        self,
        documents: list[str],
        k1: float = DEFAULT_BM25_K1,
        b: float = DEFAULT_BM25_B,
        max_df_ratio: float | None = DEFAULT_MAX_DF_RATIO,
    ):
        self.k1 = k1
        self.b = b
        self.max_df_ratio = max_df_ratio
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

    def score_document(self, query_tokens: list[str], document_index: int) -> float:
        if self.num_docs == 0:
            return 0.0
        doc_length = self.doc_lengths[document_index]
        if doc_length == 0 or self.avg_doc_length == 0:
            return 0.0

        term_counts = self.term_freqs[document_index]
        score = 0.0
        for token in set(query_tokens):
            tf = term_counts.get(token, 0)
            if tf == 0:
                continue
            if self.max_df_ratio is not None:
                df_ratio = self.doc_freq.get(token, 0) / self.num_docs
                if df_ratio > self.max_df_ratio:
                    continue
            numerator = tf * (self.k1 + 1)
            denominator = tf + self.k1 * (
                1 - self.b + self.b * doc_length / self.avg_doc_length
            )
            score += self.idf(token) * numerator / denominator
        return score

    def score(self, query_tokens: list[str]) -> list[float]:
        return [self.score_document(query_tokens, i) for i in range(self.num_docs)]


class SASTRetriever:
    """Read-only runtime retriever over the bundled prebuilt BM25 rule model."""

    def __init__(self, model_dir: str | Path = DEFAULT_MODEL_DIR):
        self.model_dir = Path(model_dir)
        self.rules = json.loads(
            (self.model_dir / "rules.json").read_text(encoding="utf-8")
        )
        self.documents = json.loads(
            (self.model_dir / "documents.json").read_text(encoding="utf-8")
        )
        self.metadata = json.loads(
            (self.model_dir / "metadata.json").read_text(encoding="utf-8")
        )

        params = self.metadata.get("bm25_parameters", {})
        self.k1 = float(params.get("k1", DEFAULT_BM25_K1))
        self.b = float(params.get("b", DEFAULT_BM25_B))
        stored_max_df_ratio = params.get("max_df_ratio", DEFAULT_MAX_DF_RATIO)
        self.max_df_ratio = (
            None if stored_max_df_ratio is None else float(stored_max_df_ratio)
        )

    def rank(
        self,
        item: dict[str, Any],
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        query_tokens = tokenize(item_to_text(item))
        if not query_tokens:
            return []

        candidate_language = item_language(item)
        applicable_rules: list[dict[str, Any]] = []
        applicable_documents: list[str] = []

        for rule, document in zip(self.rules, self.documents):
            if not languages_compatible(
                candidate_language,
                str(rule.get("language") or ""),
            ):
                continue
            applicable_rules.append(rule)
            applicable_documents.append(document)

        if not applicable_rules:
            return []

        bm25 = BM25(
            applicable_documents,
            k1=self.k1,
            b=self.b,
            max_df_ratio=self.max_df_ratio,
        )
        raw_scores = bm25.score(query_tokens)

        best_by_cwe: dict[str, tuple[float, dict[str, Any]]] = {}
        for index, rule in enumerate(applicable_rules):
            raw_score = float(raw_scores[index])
            if raw_score <= 0:
                continue
            cwe_id = str(rule.get("cwe_id") or "UNKNOWN")
            current = best_by_cwe.get(cwe_id)
            if current is None or raw_score > current[0]:
                best_by_cwe[cwe_id] = (raw_score, rule)

        ranked = sorted(
            best_by_cwe.values(),
            key=lambda row: row[0],
            reverse=True,
        )[:top_k]

        results: list[dict[str, Any]] = []
        for rank, (raw_score, rule) in enumerate(ranked, start=1):
            results.append(
                {
                    "rank": rank,
                    "rule_id": rule.get("rule_id"),
                    "cwe_id": rule.get("cwe_id"),
                    "cwe_name": rule.get("cwe_name"),
                    "language": rule.get("language"),
                    "severity": rule.get("severity"),
                    "sast_tool": rule.get("sast_tool"),
                    "is_fallback": (
                        str(rule.get("sast_tool") or "").lower() == "cwe-fallback"
                    ),
                    "score": round(raw_score, 4),
                    "raw_bm25_score": round(raw_score, 4),
                    "description": rule.get("description"),
                    "pattern": rule.get("pattern"),
                    "remediation": rule.get("remediation"),
                    "tags": rule.get("tags"),
                    "untrusted_hypothesis": True,
                }
            )
        return results


def model_exists(model_dir: str | Path = DEFAULT_MODEL_DIR) -> bool:
    model_dir = Path(model_dir)
    required = ("metadata.json", "rules.json", "documents.json")
    if not all((model_dir / name).is_file() for name in required):
        return False
    try:
        metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
    except Exception:
        return False
    return metadata.get("algorithm") == "rule_bm25_cwe_retriever"
