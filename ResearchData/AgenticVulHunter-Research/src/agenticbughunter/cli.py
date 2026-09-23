from __future__ import annotations

import argparse
import importlib.resources as ir
import json
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .pipeline import PipelineExecutionError, SecureReviewPipeline
from .research_diff import (
    available_diff_ids,
    diff_id_from_setup_script,
    load_bundled_diff,
)


def _run_experiment(args: argparse.Namespace) -> int:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise NotADirectoryError(
            f"Repository knowledge-base directory not found: {repo}"
        )
    if args.config:
        cfg = load_config(args.config)
    else:
        resource = ir.files("agenticbughunter") / "research_data" / "experiment.toml"
        with ir.as_file(resource) as config_path:
            cfg = load_config(config_path)

    if args.annotated_diff:
        annotated_path = Path(args.annotated_diff).expanduser().resolve()
        annotated = annotated_path.read_text(encoding="utf-8", errors="replace")
        diff_id = (args.diff_id or annotated_path.stem).lower()
        raw = (
            Path(args.raw_diff)
            .expanduser()
            .resolve()
            .read_text(encoding="utf-8", errors="replace")
            if args.raw_diff
            else None
        )
    else:
        diff_id = (args.diff_id or "").strip().lower()
        if not diff_id:
            diff_id = diff_id_from_setup_script(args.setup_script)
        annotated = load_bundled_diff(diff_id, "annotated")
        raw = load_bundled_diff(diff_id, "raw")

    if not args.json:
        print("AgenticVulHunter research experiment")
        print(f"  diff id: {diff_id}")
        print("  Stage 1 input: frozen [A,D,C] annotated diff")
        print("  Stage 1 prompt: previous staged prompt")
        print(f"  repository: {repo}")

    result = SecureReviewPipeline(cfg).run_annotated(
        repo,
        annotated_diff=annotated,
        raw_diff=raw,
        diff_id=diff_id,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


def _list_diffs(_args: argparse.Namespace) -> int:
    for value in available_diff_ids():
        print(value)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="avh-research",
        description="AgenticVulHunter SCRBench research experiment",
    )
    parser.add_argument(
        "--version", action="version", version=f"AgenticVulHunter {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("experiment", help="Run one prepared SCRBench case")
    p.add_argument("--repo", default="/workspace/repo")
    p.add_argument(
        "--config",
        default=None,
        help="optional TOML override; otherwise the bundled frozen experiment.toml is used",
    )
    p.add_argument("--diff-id", default=None, help="40-character SCRBench commit id")
    p.add_argument("--setup-script", default="/workspace/setup_repo.sh")
    p.add_argument(
        "--annotated-diff",
        default=None,
        help="explicit [A,D,C] diff instead of bundled lookup",
    )
    p.add_argument(
        "--raw-diff", default=None, help="optional matching raw diff for provenance"
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_run_experiment)

    p = sub.add_parser("diffs", help="List bundled SCRBench diff ids")
    p.set_defaults(func=_list_diffs)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except PipelineExecutionError as exc:
        path = exc.run_dir / "result.json"
        if path.is_file():
            print(path.read_text(encoding="utf-8"), end="", file=sys.stderr)
        else:
            print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"avh-research: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
