"""Command line entry point for AgenticVulHunter.

The public command stays small. A review uses threshold 0.6 by default and the
connection can be supplied through AVH exports or avh_setup.toml.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .pipeline import PipelineExecutionError, SecureReviewPipeline
from .ui import TerminalUI


def _threshold(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "threshold must be a number between 0.0 and 1.0"
        ) from exc
    if not 0.0 <= number <= 1.0:
        raise argparse.ArgumentTypeError("threshold must be between 0.0 and 1.0")
    return number


def _load_config(path: str | None):
    if path:
        return load_config(path)
    local = Path("avh_setup.toml")
    return load_config(local) if local.is_file() else load_config()


def _run_review(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    ui = None if args.json else TerminalUI(
        threshold=args.threshold,
        model=config.llm.model,
        endpoint=config.llm.base_url,
    )
    if ui:
        ui.render()

    try:
        result = SecureReviewPipeline(
            config,
            progress=ui.event if ui else None,
        ).run(
            args.repo,
            base=args.base,
            head=args.head,
            threshold=args.threshold,
        )
    finally:
        if ui:
            ui.finish()

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0

    print(f"AgenticVulHunter review complete (threshold {args.threshold:.2f})")
    if not result.comments:
        print("No findings passed the threshold.")
        return 0

    for comment in result.comments:
        print(
            f"{comment['filepath']}:{comment['line_number']} "
            f"[{comment['judge_final_score']:.2f}] "
            f"{comment['review_comment']}"
        )
    return 0

def _run_init(args: argparse.Namespace) -> int:
    setup_file = Path("avh_setup.toml")    
    if setup_file.exists():
        print("avh_setup.toml already exists.")
        return 0
    setup_file.write_text(
        """[llm]
endpoint = "http://localhost:11434/v1"
api_key = ""
""",
        encoding="utf-8",
    )

    print("Created avh_setup.toml")
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agenticvulhunter",
        description="Four-stage agentic secure code review",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"AgenticVulHunter {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser(
        "init",
        help="Create avh_setup.toml",
    )
    init.set_defaults(func=_run_init)    
    
    review = subparsers.add_parser("review", help="Review the current Git change")
    review.add_argument(
        "threshold",
        nargs="?",
        type=_threshold,
        default=0.6,
        help="Stage 4 acceptance threshold (default: 0.6)",
    )
    review.add_argument("--repo", default=".", help="Git repository to review")
    review.add_argument("--base", default=None, help="Optional base Git ref")
    review.add_argument("--head", default="HEAD", help="Head Git ref")
    review.add_argument(
        "--config",
        default=None,
        help="Setup file containing only [llm] endpoint and api_key",
    )
    review.add_argument("--json", action="store_true", help="Print full JSON output")
    review.set_defaults(func=_run_review)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Keep Ctrl+C predictable even while a model request is running.
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, signal.default_int_handler)

    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\nAgenticVulHunter: interrupted", file=sys.stderr)
        return 130
    except PipelineExecutionError as exc:
        result_path = exc.run_dir / "result.json"
        if result_path.is_file():
            print(result_path.read_text(encoding="utf-8"), end="", file=sys.stderr)
        else:
            print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"agenticvulhunter: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
