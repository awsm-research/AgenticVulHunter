from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import load_config
from .git import GitError, repo_root, resolve_default_base
from .pipeline import PipelineExecutionError, SecureReviewPipeline


CONFIG_NAME = ".agenticbughunter.toml"
STATE_DIR = ".agenticbughunter"
HOOK_BEGIN = "# >>> agenticbughunter managed gate >>>"
HOOK_END = "# <<< agenticbughunter managed gate <<<"

EXAMPLE_CONFIG = """[llm]
base_url = "http://localhost:11434/v1"
api_key = "ollama"
model = "qwen3-coder:30b"
timeout_seconds = 300
max_tokens = 6000
temperature = 0.0

[bm25]
endpoint = "http://localhost:5056/predict"
timeout_seconds = 120
top_k = 10
max_requests_per_candidate = 4

[pipeline]
max_candidates = 5
max_hypotheses = 5
confidence_threshold = 0.75
max_comments = 5
block_on_findings = true
isolate_worktree = true
keep_worktree = false

[agents]
stage1_max_steps = 4
stage2_max_steps = 10
stage3_max_steps = 8
stage4_mode = "api"
stage4_max_steps = 5

[repository]
context_radius = 20
max_read_lines = 220
max_search_results = 30
"""

HOOK_BLOCK = f'''{HOOK_BEGIN}
run_agenticbughunter() {{
  if command -v agenticbughunter >/dev/null 2>&1; then
    agenticbughunter "$@"
  elif command -v python3 >/dev/null 2>&1 && python3 -c 'import agenticbughunter' >/dev/null 2>&1; then
    python3 -m agenticbughunter.cli "$@"
  else
    echo "AgenticBugHunter: command not found. Install AgenticBugHunter before pushing." >&2
    return 2
  fi
}}

abh_remote_name="${{1:-origin}}"
abh_zero=0000000000000000000000000000000000000000
while read -r abh_local_ref abh_local_sha abh_remote_ref abh_remote_sha; do
  [ "$abh_local_sha" = "$abh_zero" ] && continue
  if [ "$abh_remote_sha" = "$abh_zero" ]; then
    echo "AgenticBugHunter reviewing new branch $abh_local_sha"
    run_agenticbughunter gate --repo "$(git rev-parse --show-toplevel)" --head "$abh_local_sha" || exit $?
  else
    if ! git cat-file -e "$abh_remote_sha^{{commit}}" 2>/dev/null; then
      echo "AgenticBugHunter fetching remote base $abh_remote_ref"
      git fetch --quiet "$abh_remote_name" "$abh_remote_ref" || {{
        echo "AgenticBugHunter: unable to fetch remote base $abh_remote_ref" >&2
        exit 2
      }}
    fi
    echo "AgenticBugHunter reviewing $abh_remote_sha...$abh_local_sha"
    run_agenticbughunter gate --repo "$(git rev-parse --show-toplevel)" --base "$abh_remote_sha" --head "$abh_local_sha" || exit $?
  fi
done
{HOOK_END}'''



def _config_path(repo: Path, explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit).expanduser().resolve()
    local = repo / CONFIG_NAME
    return local if local.is_file() else None


def _git_hooks_dir(repo: Path) -> Path:
    raw = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--git-path", "hooks"],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()
    path = Path(raw)
    return path if path.is_absolute() else (repo / path).resolve()


def _ensure_gitignore(repo: Path) -> None:
    path = repo / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    lines = existing.splitlines()
    if f"{STATE_DIR}/" in lines or STATE_DIR in lines:
        return
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    path.write_text(existing + prefix + f"\n# AgenticBugHunter local run artifacts\n{STATE_DIR}/\n", encoding="utf-8")


def _install_hook(repo: Path, *, force: bool = False) -> tuple[Path, str]:
    hook = _git_hooks_dir(repo) / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    existing = hook.read_text(encoding="utf-8", errors="replace") if hook.is_file() else ""
    if HOOK_BEGIN in existing and HOOK_END in existing:
        hook.chmod(0o755)
        return hook, "already-installed"

    if existing:
        first = existing.splitlines()[0] if existing.splitlines() else ""
        shell_compatible = first.startswith("#!") and any(x in first for x in ("sh", "bash", "zsh", "dash"))
        if shell_compatible:
            lines = existing.splitlines()
            shebang = lines[0]
            remainder = "\n".join(lines[1:]).lstrip("\n")
            content = shebang + "\n\n" + HOOK_BLOCK + "\n\n" + remainder
            if not content.endswith("\n"):
                content += "\n"
            action = "chained"
        elif force:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = hook.with_name(f"pre-push.agenticbughunter-backup-{stamp}")
            shutil.copy2(hook, backup)
            content = "#!/bin/sh\nset -eu\n\n" + HOOK_BLOCK + "\n"
            action = f"replaced (backup: {backup.name})"
        else:
            raise RuntimeError(
                f"Existing pre-push hook is not a shell hook: {hook}. "
                "Use 'agenticbughunter install-hook --force' to back it up and replace it."
            )
    else:
        content = "#!/bin/sh\nset -eu\n\n" + HOOK_BLOCK + "\n"
        action = "installed"

    hook.write_text(content, encoding="utf-8")
    hook.chmod(0o755)
    return hook, action


def _uninstall_hook(repo: Path) -> tuple[Path, bool]:
    hook = _git_hooks_dir(repo) / "pre-push"
    if not hook.is_file():
        return hook, False
    text = hook.read_text(encoding="utf-8", errors="replace")
    start = text.find(HOOK_BEGIN)
    end = text.find(HOOK_END)
    if start < 0 or end < start:
        return hook, False
    end += len(HOOK_END)
    remaining = (text[:start].rstrip() + "\n" + text[end:].lstrip()).strip()
    if remaining in {"#!/bin/sh", "#!/bin/sh\nset -eu", "#!/usr/bin/env sh", "#!/usr/bin/env bash"}:
        hook.unlink(missing_ok=True)
    else:
        hook.write_text(remaining + "\n", encoding="utf-8")
        hook.chmod(0o755)
    return hook, True


def cmd_init(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    path = repo / CONFIG_NAME
    if path.exists() and not args.force:
        print(f"Config already exists: {path}")
    else:
        path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
        print(f"Created {path}")

    (repo / STATE_DIR / "runs").mkdir(parents=True, exist_ok=True)
    _ensure_gitignore(repo)
    print(f"Runtime state: {repo / STATE_DIR}")

    if not args.no_hook:
        try:
            hook, action = _install_hook(repo, force=False)
            print(f"Pre-push hook: {action} ({hook})")
        except RuntimeError as exc:
            print(f"Hook not installed: {exc}", file=sys.stderr)
    print("Configure [llm] and your existing [bm25].endpoint, then run: agenticbughunter doctor")
    return 0


def _run(args: argparse.Namespace, gate: bool) -> int:
    repo = repo_root(args.repo)
    cfg = load_config(_config_path(repo, args.config))
    result = SecureReviewPipeline(cfg).run(repo, base=args.base, head=args.head)
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"AgenticBugHunter: {result.status.upper()}  run={result.run_id}")
        print(f"Logs: {result.run_dir}")
        if result.findings:
            for finding in result.findings:
                change_type = str(finding.assessment.get("change_type") or "A")
                print(f"\n{finding.filepath}:{finding.changed_line} [{change_type}]  {finding.cwe_id}  score={finding.final_score:.3f}")
                print(finding.review_comment)
        else:
            print("No supported findings passed the configured threshold.")
    return 1 if gate and result.status == "block" else 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    hook, action = _install_hook(repo, force=args.force)
    print(f"AgenticBugHunter pre-push hook {action}: {hook}")
    return 0


def cmd_uninstall_hook(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    hook, changed = _uninstall_hook(repo)
    if changed:
        print(f"Removed AgenticBugHunter block from {hook}")
    else:
        print(f"No managed AgenticBugHunter hook found at {hook}")
    return 0


def cmd_show_run(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    runs = repo / STATE_DIR / "runs"
    if args.run_id:
        path = runs / args.run_id / "result.json"
    else:
        choices = sorted((p for p in runs.glob("*") if p.is_dir()), reverse=True) if runs.is_dir() else []
        if not choices:
            print("No AgenticBugHunter runs found.")
            return 1
        path = choices[0] / "result.json"
    if not path.is_file():
        print(f"Run result not found: {path}")
        return 1
    print(path.read_text(encoding="utf-8"), end="")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    config_path = _config_path(repo, args.config)
    cfg = load_config(config_path)
    print("AgenticBugHunter doctor")
    print(f"  repo:   {repo}")
    print(f"  config: {config_path or '(built-in defaults)'}")
    print(f"  llm:    {cfg.llm.base_url}  model={cfg.llm.model}")
    print(f"  bm25:   {cfg.bm25.endpoint}")
    try:
        base = resolve_default_base(repo, head=args.head)
        print(f"  base:   {base}")
    except GitError as exc:
        print(f"  base:   WARNING: {exc}")
    hook = _git_hooks_dir(repo) / "pre-push"
    managed = hook.is_file() and HOOK_BEGIN in hook.read_text(encoding="utf-8", errors="replace")
    print(f"  hook:   {'managed' if managed else 'not installed'}")
    print("Configuration and package checks passed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agenticbughunter", description="Project-local agentic secure-code-review Git gate")
    parser.add_argument("--version", action="version", version="AgenticBugHunter 0.2.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Add AgenticBugHunter configuration/runtime state to a Git project")
    p.add_argument("--repo", default=".")
    p.add_argument("--force", action="store_true", help="overwrite the project config")
    p.add_argument("--no-hook", action="store_true", help="do not install the managed pre-push hook")
    p.set_defaults(func=cmd_init)

    for name, gate in (("review", False), ("gate", True)):
        p = sub.add_parser(name, help="Run staged secure code review" + (" and fail on supported findings" if gate else ""))
        p.add_argument("--repo", default=".")
        p.add_argument("--base", default=None, help="Base Git ref; defaults to upstream/origin default branch/HEAD~1, never HEAD itself")
        p.add_argument("--head", default="HEAD")
        p.add_argument("--config", default=None)
        p.add_argument("--json", action="store_true", help="write only result JSON to stdout")
        p.set_defaults(func=lambda a, g=gate: _run(a, g))

    p = sub.add_parser("install-hook", help="Install/update the managed project pre-push gate")
    p.add_argument("--repo", default=".")
    p.add_argument("--force", action="store_true", help="backup and replace an incompatible existing hook")
    p.set_defaults(func=cmd_install_hook)

    p = sub.add_parser("uninstall-hook", help="Remove only the AgenticBugHunter managed hook block")
    p.add_argument("--repo", default=".")
    p.set_defaults(func=cmd_uninstall_hook)

    p = sub.add_parser("show-run", help="Print a saved run result, including failed runs")
    p.add_argument("--repo", default=".")
    p.add_argument("run_id", nargs="?")
    p.set_defaults(func=cmd_show_run)

    p = sub.add_parser("doctor", help="Validate project/package configuration without running the LLM pipeline")
    p.add_argument("--repo", default=".")
    p.add_argument("--config", default=None)
    p.add_argument("--head", default="HEAD")
    p.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("AgenticBugHunter: interrupted", file=sys.stderr)
        return 130
    except PipelineExecutionError as exc:
        print(f"AgenticBugHunter: {exc}", file=sys.stderr)
        print(f"Logs: {exc.run_dir}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"AgenticBugHunter: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
