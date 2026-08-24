"""Evaluate whether the true CWE appears in the top-k retrieved CWE hypotheses."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from stage2_5_retriever_core import FILES_DIR, PROJECT_DIR, load_or_build_model, normalize_cwe, resolve_path


def parse_extra_rules(value: str | None, files_dir: Path) -> list[Path] | None:
    # None means use the core default fallback file. Empty string means disable fallback rules.
    if value is None:
        return None
    if value == "":
        return []

    paths = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        path = Path(part).expanduser()
        if not path.is_absolute():
            path = files_dir / path
        paths.append(path)
    return paths


def load_json_or_jsonl(path: Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    if not text:
        return []

    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    rows = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"Bad JSON on line {line_number} in {path}: {error}") from error
        if isinstance(row, dict):
            rows.append(row)

    return rows


def get_true_cwes(row: dict[str, Any]) -> list[str]:
    values = []

    for key in ["cwe_id", "cwe", "cwe_ids", "vuln_type", "vulnerability_type"]:
        value = row.get(key)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(value)

    result = []
    for value in values:
        cwe = normalize_cwe(value)
        if cwe and cwe not in result:
            result.append(cwe)

    return result


def file_from_diff(diff: str) -> str:
    match = re.search(r"diff --git a/(.*?) b/", str(diff))
    return match.group(1) if match else ""


def added_lines_from_diff(diff: str) -> str:
    lines = []
    for line in str(diff).splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            lines.append(line[1:])
    return "\n".join(lines)


def item_from_diff(row: dict[str, Any]) -> dict[str, Any]:
    diff = row.get("diff", "")
    return {
        "diff_id": row.get("diff_id"),
        "filepath": file_from_diff(diff),
        "statement": added_lines_from_diff(diff) or diff,
        "operation_type": "",
        "source_summary": "",
        "sink_summary": "",
        "guard_summary": "",
        "risk_pattern": "",
        "called_apis": [],
        "context_summary": diff,
    }


def unique(values: list[Any]) -> list[str]:
    result = []
    for value in values:
        cwe = normalize_cwe(value)
        if cwe and cwe not in result:
            result.append(cwe)
    return result


def hit(true_cwes: list[str], predicted_cwes: list[str], k: int) -> bool:
    return any(cwe in predicted_cwes[:k] for cwe in true_cwes)


def reciprocal_rank(true_cwes: list[str], predicted_cwes: list[str]) -> float:
    true_set = set(true_cwes)
    for index, cwe in enumerate(predicted_cwes, start=1):
        if cwe in true_set:
            return 1.0 / index
    return 0.0


def make_summary(name: str, frame: pd.DataFrame) -> dict[str, Any]:
    return {
        "split": name,
        "rows": len(frame),
        "top1_accuracy": frame["top1_hit"].mean(),
        "top3_accuracy": frame["top3_hit"].mean(),
        "top5_accuracy": frame["top5_hit"].mean(),
        "top10_accuracy": frame["top10_hit"].mean(),
        "mrr": frame["reciprocal_rank"].mean(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Stage 2.5 CWE-grouped BM25 retrieval accuracy.")
    parser.add_argument("--files-dir", default=str(FILES_DIR))
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--groundtruth", default=None)
    parser.add_argument("--sast", default=None)
    parser.add_argument("--extra-rules", default=None)
    parser.add_argument("--model-dir", default=None)
    parser.add_argument("--results-csv", default=None)
    parser.add_argument("--summary-csv", default=None)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()

    files_dir = resolve_path(args.files_dir, PROJECT_DIR)
    dataset_path = resolve_path(args.dataset, PROJECT_DIR) if args.dataset else files_dir / "dataset_easy_to_read.jsonl"
    groundtruth_path = resolve_path(args.groundtruth, PROJECT_DIR) if args.groundtruth else files_dir / "groundtruth.jsonl"
    sast_path = resolve_path(args.sast, PROJECT_DIR) if args.sast else files_dir / "sast.json"
    model_dir = resolve_path(args.model_dir, PROJECT_DIR) if args.model_dir else files_dir / "stage2_5_model"
    results_csv = resolve_path(args.results_csv, PROJECT_DIR) if args.results_csv else files_dir / "stage2_5_cwe_accuracy_results.csv"
    summary_csv = resolve_path(args.summary_csv, PROJECT_DIR) if args.summary_csv else files_dir / "stage2_5_cwe_accuracy_summary.csv"
    extra_rule_paths = parse_extra_rules(args.extra_rules, files_dir)

    retriever = load_or_build_model(
        model_dir=model_dir,
        sast_path=sast_path,
        extra_rule_paths=extra_rule_paths,
        rebuild=args.rebuild,
    )

    print("Retriever:")
    print(json.dumps(retriever.metadata, indent=2))

    dataset = load_json_or_jsonl(dataset_path)
    groundtruth = load_json_or_jsonl(groundtruth_path)

    print(f"\nDataset rows: {len(dataset)}")
    print(f"Groundtruth rows: {len(groundtruth)}")

    truth_by_diff = defaultdict(set)
    for row in groundtruth:
        diff_id = row.get("diff_id")
        if not diff_id:
            continue
        for cwe in get_true_cwes(row):
            truth_by_diff[diff_id].add(cwe)

    print(f"Groundtruth diff_ids: {len(truth_by_diff)}")

    rule_cwes = {normalize_cwe(rule.get("cwe_id")) for rule in retriever.rules}
    print(f"Unique CWEs in rule base: {len(rule_cwes)}")

    rows = []

    for row in dataset:
        diff_id = row.get("diff_id")
        if diff_id not in truth_by_diff:
            continue

        true_cwes = sorted(truth_by_diff[diff_id])
        ranked_rules = retriever.rank(item_from_diff(row), top_k=args.top_k)
        predicted_cwes = unique([rule.get("cwe_id") for rule in ranked_rules])

        rows.append({
            "diff_id": diff_id,
            "true_cwes": true_cwes,
            "predicted_cwes": predicted_cwes,
            "top1_hit": hit(true_cwes, predicted_cwes, 1),
            "top3_hit": hit(true_cwes, predicted_cwes, 3),
            "top5_hit": hit(true_cwes, predicted_cwes, 5),
            "top10_hit": hit(true_cwes, predicted_cwes, 10),
            "reciprocal_rank": reciprocal_rank(true_cwes, predicted_cwes),
            "true_cwe_in_rules": any(cwe in rule_cwes for cwe in true_cwes),
        })

    results = pd.DataFrame(rows)
    if results.empty:
        print("No rows evaluated. Check diff_id values.")
        return

    print(f"\nEvaluated rows: {len(results)}")

    summaries = [make_summary("all_rows", results)]
    retrievable = results[results["true_cwe_in_rules"]]
    if not retrievable.empty:
        summaries.append(make_summary("retrievable_only", retrievable))

    summary_df = pd.DataFrame(summaries)
    print("\nSummary:")
    print(summary_df.to_string(index=False))

    results_csv.parent.mkdir(parents=True, exist_ok=True)
    summary_csv.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(results_csv, index=False)
    summary_df.to_csv(summary_csv, index=False)

    print(f"\nSaved {results_csv}")
    print(f"Saved {summary_csv}")


if __name__ == "__main__":
    main()
