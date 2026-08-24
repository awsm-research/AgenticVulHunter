from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent
FILES_DIR = PROJECT_DIR / "files"

DEFAULT_SAST_PATH = FILES_DIR / "sast.json"
DEFAULT_EXTRA_RULES = FILES_DIR / "scrbench_cwe_fallback_rules.json"
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


def resolve_path(
    path: str | Path | None,
    base_dir: Path = PROJECT_DIR,
) -> Path:
    if path is None:
        return base_dir

    path = Path(path).expanduser()

    if path.is_absolute():
        return path

    return base_dir / path


def split_identifier(token: str) -> list[str]:
    pieces = re.split(r"[._/\-]+", token)
    result = []

    for piece in pieces:
        if not piece:
            continue

        expanded = re.sub(
            r"([a-z0-9])([A-Z])",
            r"\1 \2",
            piece,
        )

        expanded = re.sub(
            r"([A-Z]+)([A-Z][a-z])",
            r"\1 \2",
            expanded,
        )

        for part in expanded.lower().split():
            if len(part) >= 2:
                result.append(part)

    return result


def tokenize(value: str) -> list[str]:
    text = str(value or "")

    raw_tokens = re.findall(
        r"[A-Za-z_][A-Za-z0-9_./-]*|CWE[-_ ]?\d+|\d+",
        text,
    )

    tokens = []

    for raw_token in raw_tokens:
        cwe = normalize_cwe(raw_token)

        if cwe.startswith("CWE-"):
            tokens.append(cwe.lower())
            continue

        tokens.append(raw_token.lower())
        tokens.extend(split_identifier(raw_token))

    return tokens


def load_json_list(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list")

    return [
        item
        for item in data
        if isinstance(item, dict)
    ]


def clean_rule(rule: dict[str, Any]) -> dict[str, Any] | None:
    rule_id = str(rule.get("rule_id") or "").strip()
    cwe_id = normalize_cwe(rule.get("cwe_id"))

    if not rule_id or not cwe_id:
        return None

    return {
        **rule,
        "rule_id": rule_id,
        "cwe_id": cwe_id,
        "cwe_name": str(rule.get("cwe_name") or "").strip(),
        "language": str(rule.get("language") or "").strip().lower(),
    }


def load_rules(
    sast_path: str | Path = DEFAULT_SAST_PATH,
    extra_rule_paths: list[str | Path] | None = None,
) -> list[dict[str, Any]]:
    all_rules = load_json_list(sast_path)

    # By default, include the fallback CWE rules in the same BM25 corpus.
    # Passing [] explicitly disables them.
    if extra_rule_paths is None:
        extra_rule_paths = [DEFAULT_EXTRA_RULES]

    for path in extra_rule_paths:
        path = Path(path)

        if path.exists():
            all_rules.extend(load_json_list(path))

    rules = []
    seen_rule_ids = set()

    for raw_rule in all_rules:
        rule = clean_rule(raw_rule)

        if not rule:
            continue

        if rule["rule_id"] in seen_rule_ids:
            continue

        seen_rule_ids.add(rule["rule_id"])
        rules.append(rule)

    return rules


def example_vulnerability_tokens(examples: Any) -> list[str]:
    if not isinstance(examples, list):
        return []

    tokens = set()

    for example in examples:
        if not isinstance(example, dict):
            continue

        bad = as_text(example.get("bad"))
        good = as_text(example.get("good"))

        if not bad:
            continue

        bad_tokens = set(tokenize(bad))
        good_tokens = set(tokenize(good))

        tokens.update(bad_tokens - good_tokens)

    return sorted(tokens)


def rule_to_text(rule: dict[str, Any]) -> str:
    example_tokens = example_vulnerability_tokens(
        rule.get("examples")
    )

    parts = [
        as_text(rule.get("cwe_name")),
        as_text(rule.get("rule_id")),
        as_text(rule.get("description")),
        as_text(rule.get("pattern")),
        as_text(rule.get("tags")),
        as_text(rule.get("caused_by")),
        as_text(rule.get("led_to")),
        " ".join(example_tokens),
        as_text(rule.get("language")),
    ]

    return " ".join(
        part.strip()
        for part in parts
        if part and part.strip()
    )


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
    ]

    parts = []

    for value in fields:
        text = as_text(value).strip()

        if text:
            parts.append(text)

    return " ".join(parts)


def item_language(item: dict[str, Any]) -> str:
    language = str(
        item.get("language") or ""
    ).strip().lower()

    if language:
        return language

    filepath = str(
        item.get("filepath")
        or item.get("file")
        or ""
    )

    return EXTENSION_TO_LANGUAGE.get(
        Path(filepath).suffix.lower(),
        "",
    )


def normalize_language(language: str) -> str:
    aliases = {
        "py": "python",
        "js": "javascript",
        "ts": "typescript",
        "cs": "csharp",
    }

    language = str(language or "").strip().lower()

    return aliases.get(language, language)


def languages_compatible(
    candidate_language: str,
    rule_language: str,
) -> bool:
    candidate = normalize_language(candidate_language)
    rule = normalize_language(rule_language)

    if not candidate or not rule:
        return True

    # Fallback rules are intentionally language-independent.
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

        self.doc_tokens = [
            tokenize(document)
            for document in documents
        ]

        self.doc_lengths = [
            len(tokens)
            for tokens in self.doc_tokens
        ]

        self.avg_doc_length = (
            sum(self.doc_lengths) / len(self.doc_lengths)
            if self.doc_lengths
            else 0.0
        )

        self.term_freqs = [
            Counter(tokens)
            for tokens in self.doc_tokens
        ]

        self.doc_freq = Counter()

        for counts in self.term_freqs:
            for token in counts:
                self.doc_freq[token] += 1

        self.num_docs = len(self.doc_tokens)

    def idf(self, token: str) -> float:
        df = self.doc_freq.get(token, 0)

        return math.log(
            1
            + (self.num_docs - df + 0.5)
            / (df + 0.5)
        )

    def score_document(
        self,
        query_tokens: list[str],
        document_index: int,
    ) -> float:
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

            # Generic corpus-frequency suppression:
            # if a term occurs in too much of the applicable SAST corpus,
            # it is not discriminative enough to influence CWE ranking.
            #
            # This is CWE-independent and benchmark-independent. It is
            # computed from the language-filtered rule corpus for this query.
            if self.max_df_ratio is not None and self.num_docs > 0:
                df_ratio = self.doc_freq.get(token, 0) / self.num_docs
                if df_ratio > self.max_df_ratio:
                    continue

            numerator = tf * (self.k1 + 1)

            denominator = tf + self.k1 * (
                1
                - self.b
                + self.b
                * doc_length
                / self.avg_doc_length
            )

            score += (
                self.idf(token)
                * numerator
                / denominator
            )

        return score

    def score(self, query_tokens: list[str]) -> list[float]:
        return [
            self.score_document(query_tokens, i)
            for i in range(self.num_docs)
        ]


def build_model(
    sast_path: str | Path = DEFAULT_SAST_PATH,
    model_dir: str | Path = DEFAULT_MODEL_DIR,
    extra_rule_paths: list[str | Path] | None = None,
    k1: float = DEFAULT_BM25_K1,
    b: float = DEFAULT_BM25_B,
    max_df_ratio: float | None = DEFAULT_MAX_DF_RATIO,
) -> dict[str, Any]:
    sast_path = Path(sast_path)
    model_dir = Path(model_dir)

    if extra_rule_paths is None:
        extra_rule_paths = [DEFAULT_EXTRA_RULES]

    extra_rule_paths = [
        Path(path)
        for path in extra_rule_paths
        if Path(path).exists()
    ]

    rules = load_rules(
        sast_path,
        extra_rule_paths,
    )

    documents = [
        rule_to_text(rule)
        for rule in rules
    ]

    model_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    fallback_rule_count = sum(
        str(rule.get("sast_tool") or "").lower() == "cwe-fallback"
        for rule in rules
    )

    metadata = {
        "algorithm": "rule_bm25_cwe_retriever",
        "description": (
            "BM25 ranks base SAST and fallback CWE rules together, "
            "then keeps the highest ranked rule for each CWE."
        ),
        "bm25_parameters": {
            "k1": k1,
            "b": b,
            "max_df_ratio": max_df_ratio,
        },
        "base_sast_file": str(sast_path),
        "extra_rule_files": [
            str(path)
            for path in extra_rule_paths
        ],
        "rule_count": len(rules),
        "fallback_rule_count": fallback_rule_count,
        "cwe_count": len({
            rule["cwe_id"]
            for rule in rules
        }),
    }

    (model_dir / "rules.json").write_text(
        json.dumps(
            rules,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    (model_dir / "documents.json").write_text(
        json.dumps(
            documents,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    (model_dir / "metadata.json").write_text(
        json.dumps(
            metadata,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return metadata


def build_retriever_model(
    sast_path: str | Path = DEFAULT_SAST_PATH,
    model_dir: str | Path = DEFAULT_MODEL_DIR,
    extra_rule_paths: list[str | Path] | None = None,
    max_df_ratio: float | None = DEFAULT_MAX_DF_RATIO,
) -> dict[str, Any]:
    return build_model(
        sast_path=sast_path,
        model_dir=model_dir,
        extra_rule_paths=extra_rule_paths,
        max_df_ratio=max_df_ratio,
    )


class SASTRetriever:
    def __init__(
        self,
        model_dir: str | Path = DEFAULT_MODEL_DIR,
    ):
        self.model_dir = Path(model_dir)

        self.rules = json.loads(
            (self.model_dir / "rules.json").read_text(
                encoding="utf-8"
            )
        )

        self.documents = json.loads(
            (self.model_dir / "documents.json").read_text(
                encoding="utf-8"
            )
        )

        self.metadata = json.loads(
            (self.model_dir / "metadata.json").read_text(
                encoding="utf-8"
            )
        )

        params = self.metadata.get(
            "bm25_parameters",
            {},
        )

        self.k1 = float(
            params.get("k1", DEFAULT_BM25_K1)
        )

        self.b = float(
            params.get("b", DEFAULT_BM25_B)
        )

        stored_max_df_ratio = params.get(
            "max_df_ratio",
            DEFAULT_MAX_DF_RATIO,
        )
        self.max_df_ratio = (
            None
            if stored_max_df_ratio is None
            else float(stored_max_df_ratio)
        )

    def rank(
        self,
        item: dict[str, Any],
        top_k: int = 5,
        max_per_cwe: int | None = 1,
        min_raw_score: float | None = None,
    ) -> list[dict[str, Any]]:
        query_text = item_to_text(item)
        query_tokens = tokenize(query_text)

        if not query_tokens:
            return []

        candidate_language = item_language(item)

        applicable_rules = []
        applicable_documents = []

        for rule, document in zip(
            self.rules,
            self.documents,
        ):
            if not languages_compatible(
                candidate_language,
                str(rule.get("language") or ""),
            ):
                continue

            applicable_rules.append(rule)
            applicable_documents.append(document)

        if not applicable_rules:
            return []

        # BM25 is built over both language-specific SAST rules and
        # generic fallback rules that are applicable to this candidate.
        bm25 = BM25(
            applicable_documents,
            k1=self.k1,
            b=self.b,
            max_df_ratio=self.max_df_ratio,
        )

        raw_scores = bm25.score(query_tokens)
        best_by_cwe = {}

        for index, rule in enumerate(applicable_rules):
            raw_score = float(raw_scores[index])

            if raw_score <= 0:
                continue

            cwe_id = rule.get("cwe_id") or "UNKNOWN"
            current = best_by_cwe.get(cwe_id)

            if current is None or raw_score > current[0]:
                best_by_cwe[cwe_id] = (
                    raw_score,
                    rule,
                )

        ranked = sorted(
            best_by_cwe.values(),
            key=lambda row: row[0],
            reverse=True,
        )[:top_k]

        results = []

        for rank, (raw_score, rule) in enumerate(
            ranked,
            start=1,
        ):
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
                        str(rule.get("sast_tool") or "").lower()
                        == "cwe-fallback"
                    ),
                    "score": round(raw_score, 4),
                    "raw_bm25_score": round(raw_score, 4),
                    "description": rule.get("description"),
                    "pattern": rule.get("pattern"),
                    "remediation": rule.get("remediation"),
                    "tags": rule.get("tags"),
                    "query_file": rule.get("query_file"),
                    "untrusted_hypothesis": True,
                }
            )

        return results


def model_exists(
    model_dir: str | Path = DEFAULT_MODEL_DIR,
) -> bool:
    model_dir = Path(model_dir)

    required_files = [
        "metadata.json",
        "rules.json",
        "documents.json",
    ]

    if not all(
        (model_dir / filename).exists()
        for filename in required_files
    ):
        return False

    try:
        metadata = json.loads(
            (model_dir / "metadata.json").read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return False

    return (
        metadata.get("algorithm")
        == "rule_bm25_cwe_retriever"
    )


def load_or_build_model(
    model_dir: str | Path = DEFAULT_MODEL_DIR,
    sast_path: str | Path = DEFAULT_SAST_PATH,
    extra_rule_paths: list[str | Path] | None = None,
    rebuild: bool = False,
    max_df_ratio: float | None = DEFAULT_MAX_DF_RATIO,
) -> SASTRetriever:
    model_dir = Path(model_dir)

    if rebuild or not model_exists(model_dir):
        build_model(
            sast_path=sast_path,
            model_dir=model_dir,
            extra_rule_paths=extra_rule_paths,
            max_df_ratio=max_df_ratio,
        )

    return SASTRetriever(model_dir)