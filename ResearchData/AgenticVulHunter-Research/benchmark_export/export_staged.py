#!/usr/bin/env python3
"""Export a staged AgenticVulHunter job at one score threshold."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = ROOT / "benchmark_export" / "dataset.jsonl"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def find_trials(job, diff_ids):
    trials = {}
    for directory in job.iterdir():
        if not directory.is_dir():
            continue
        prefix = directory.name.split("__", 1)[0]
        matches = [diff_id for diff_id in diff_ids if diff_id.startswith(prefix)]
        if len(matches) == 1:
            trials[matches[0]] = directory
    return trials


def get_reviews(trial, threshold):
    if trial is None:
        return []
    path = trial / "agent/agenticvulhunter/run/stage4_judge/output.json"
    if not path.is_file():
        return []

    reviews = []
    for candidate in read_json(path):
        choices = []
        for assessment in candidate.get("cwe_assessments", []):
            if not isinstance(assessment, dict):
                continue
            text = str(assessment.get("review_comment") or "").strip()
            score = float(assessment.get("score") or 0)
            if text and score >= threshold:
                choices.append(assessment)
        if not choices:
            continue

        best = max(choices, key=lambda item: float(item.get("score") or 0))
        reviews.append(
            {
                "file": str(candidate.get("filepath") or ""),
                "line": int(candidate.get("changed_line") or 0),
                "comment": str(best["review_comment"]).strip(),
                "confidence": float(best["score"]),
                "vuln_type": [str(best.get("cwe_id") or "")],
            }
        )
    return sorted(reviews, key=lambda item: item["confidence"], reverse=True)


def get_trajectory(trial):
    empty = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "steps": 0,
        "extra": {"token_counts_available": False},
    }
    if trial is None:
        return empty

    path = trial / "agent/agenticvulhunter/run/events.jsonl"
    if not path.is_file():
        return empty

    input_tokens = 0
    output_tokens = 0
    total_tokens = 0
    calls = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("type") != "llm_call":
            continue
        usage = event.get("payload", {}).get("usage", {})
        prompt = int(usage.get("prompt_tokens") or 0)
        completion = int(usage.get("completion_tokens") or 0)
        input_tokens += prompt
        output_tokens += completion
        total_tokens += int(usage.get("total_tokens") or prompt + completion)
        calls += 1

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "steps": calls,
        "extra": {"token_counts_available": calls > 0},
    }


def main():
    parser = argparse.ArgumentParser(
        description="Export a staged AgenticVulHunter job for SCRBench."
    )
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--threshold", type=float, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--agent-id", default="AgenticVulHunter")
    parser.add_argument("--model", default="qwen3-coder:30b")
    args = parser.parse_args()

    if not 0 <= args.threshold <= 1:
        parser.error("--threshold must be between 0 and 1")
    if args.output is None:
        tag = f"{args.threshold:.2f}".replace(".", "-")
        args.output = ROOT / f"output/{args.job.name}-T{tag}.jsonl"

    dataset = [
        json.loads(line)
        for line in args.dataset.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    diff_ids = [str(row["diff_id"]) for row in dataset]
    trials = find_trials(args.job, diff_ids)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")

    rows = []
    comment_count = 0
    for diff_id in diff_ids:
        trial = trials.get(diff_id)
        reviews = get_reviews(trial, args.threshold)
        comment_count += len(reviews)
        rows.append(
            {
                "diff_id": diff_id,
                "submission": {
                    "agent_id": f"{args.agent_id}-T{args.threshold:.2f}",
                    "agent_version": "0.2.1",
                    "model": args.model,
                    "timestamp": timestamp,
                    "extra": {
                        "source_job": args.job.name,
                        "confidence_threshold": args.threshold,
                    },
                },
                "trajectory": get_trajectory(trial),
                "has_reviews": bool(reviews),
                "reviews": reviews,
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    print(f"Wrote {len(rows)} tasks and {comment_count} comments to {args.output}")


if __name__ == "__main__":
    main()
