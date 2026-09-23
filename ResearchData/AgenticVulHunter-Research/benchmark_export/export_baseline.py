#!/usr/bin/env python3
"""Convert one Harbor baseline job into SCRBench JSONL."""

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


def get_reviews(trial):
    if trial is None:
        return []
    path = trial / "verifier/comments.json"
    if not path.is_file():
        return []

    reviews = []
    for comment in read_json(path):
        text = str(comment.get("review_comment") or "").strip()
        if not text:
            continue
        vuln_type = comment.get("vuln_type") or []
        if isinstance(vuln_type, str):
            vuln_type = [vuln_type]
        reviews.append(
            {
                "file": str(comment.get("filepath") or ""),
                "line": int(comment.get("line_number") or 0),
                "comment": text,
                "vuln_type": [str(item) for item in vuln_type],
                "confidence": None,
            }
        )
    return reviews


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

    path = trial / "agent/trajectory.json"
    if not path.is_file():
        return empty

    metrics = read_json(path).get("final_metrics", {})
    input_tokens = int(metrics.get("total_prompt_tokens") or 0)
    output_tokens = int(metrics.get("total_completion_tokens") or 0)
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "steps": int(metrics.get("total_steps") or 0),
        "extra": {"token_counts_available": True},
    }


def main():
    parser = argparse.ArgumentParser(
        description="Export an AgenticSCR baseline Harbor job for SCRBench."
    )
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--agent-id", default="AgenticSCR-Qwen3-Faithful")
    parser.add_argument("--model", default="qwen3-coder:30b")
    args = parser.parse_args()

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
        reviews = get_reviews(trial)
        comment_count += len(reviews)
        if trial is None:
            status = "missing"
        elif (trial / "exception.txt").exists():
            status = "failed"
        elif (trial / "verifier/comments.json").exists():
            status = "completed"
        else:
            status = "incomplete"

        rows.append(
            {
                "diff_id": diff_id,
                "submission": {
                    "agent_id": args.agent_id,
                    "agent_version": "faithful-baseline",
                    "model": args.model,
                    "timestamp": timestamp,
                    "extra": {
                        "source_job": args.job.name,
                        "status": status,
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
