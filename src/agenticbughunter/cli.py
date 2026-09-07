from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .config import environment_overrides, load_config
from .config_edit import get_config_value, known_config_keys, set_config_value
from .dashboard import serve_dashboard
from .git import GitError, repo_root, resolve_default_base
from .models import Finding, PipelineResult, StageResult
from .pipeline import PipelineExecutionError, SecureReviewPipeline
from .ui import TerminalUI

CONFIG_NAME = ".agenticbughunter.toml"
STATE_DIR = ".agenticbughunter"
HOOK_BEGIN = "# >>> agenticbughunter managed gate >>>"
HOOK_END = "# <<< agenticbughunter managed gate <<<"
CHAIN_MARKER = "# agenticbughunter: preserved-hook-wrapper-v1"
PRESERVED_HOOK = "pre-push.agenticbughunter-original"

EXAMPLE_CONFIG = """# AgenticBugHunter project configuration
#
# Every setting can also be overridden temporarily with an ABH_* environment
# variable. Run `agenticbughunter config env` to see the full mapping.

[llm]
provider = "openai"
base_url = "http://localhost:11434/v1"
model = "qwen3-coder:30b"
timeout_seconds = 800
max_tokens = 6000
temperature = 0.0

[pipeline]
max_candidates = 3
max_hypotheses = 5
confidence_threshold = 0.80
block_on_findings = false
isolate_worktree = false
keep_worktree = false

[bm25]
top_k = 10
max_requests_per_candidate = 4

[agents]
stage1_max_steps = 50
stage2_max_steps = 50
stage3_max_steps = 50
stage4_mode = "api"
stage4_max_steps = 10

[repository]
context_radius = 200
max_read_lines = 300
max_search_results = 30

# Presentation only. These settings never change review decisions.
[ui]
banner = true
live_progress = true
show_config = true
show_stage_details = true
"""

HOOK_BLOCK = f"""{HOOK_BEGIN}
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
{HOOK_END}"""


def _config_path(repo: Path, explicit: str | None) -> Path | None:
    # Selection order: CLI --config, ABH_CONFIG, project TOML, defaults.
    if explicit:
        return Path(explicit).expanduser().resolve()
    env_path = os.getenv("ABH_CONFIG")
    if env_path:
        candidate = Path(env_path).expanduser()
        if not candidate.is_absolute():
            candidate = repo / candidate
        return candidate.resolve()
    local = repo / CONFIG_NAME
    return local if local.is_file() else None


def _active_environment_overrides() -> list[str]:
    names = [name for name in environment_overrides() if name in os.environ]
    for legacy in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL"):
        if legacy in os.environ:
            names.append(legacy)
    return sorted(set(names))


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
    path.write_text(
        existing + prefix + f"\n# AgenticBugHunter local run artifacts\n{STATE_DIR}/\n",
        encoding="utf-8",
    )


def _install_hook(repo: Path, *, force: bool = False) -> tuple[Path, str]:
    hook = _git_hooks_dir(repo) / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    existing = (
        hook.read_text(encoding="utf-8", errors="replace") if hook.is_file() else ""
    )
    if HOOK_BEGIN in existing and HOOK_END in existing:
        hook.chmod(0o755)
        return hook, "already-installed"

    if existing:
        first = existing.splitlines()[0] if existing.splitlines() else ""
        shell_compatible = first.startswith("#!") and any(
            x in first for x in ("sh", "bash", "zsh", "dash")
        )
        if shell_compatible:
            # Preserve the original byte-for-byte and replay Git's stdin for
            # each hook. Prepending two readers would starve the second one.
            preserved = hook.with_name(PRESERVED_HOOK)
            if preserved.exists():
                raise RuntimeError(
                    f"Preserved hook already exists: {preserved}; resolve it before installing"
                )
            shutil.copy2(hook, preserved)
            preserved.chmod(preserved.stat().st_mode | 0o100)
            content = (
                "#!/bin/sh\n"
                + CHAIN_MARKER
                + "\n"
                + 'abh_hook_input="$(mktemp)" || exit 2\n'
                + "trap 'rm -f \"$abh_hook_input\"' 0\n"
                + 'cat > "$abh_hook_input" || exit 2\n'
                + "(\n"
                + HOOK_BLOCK
                + '\n) < "$abh_hook_input" || exit $?\n'
                + 'abh_original="$(dirname "$0")/'
                + PRESERVED_HOOK
                + '"\n'
                + '"$abh_original" "$@" < "$abh_hook_input"\n'
            )
            action = "chained (original preserved; stdin replayed for both hooks)"
        elif force:
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
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
    if CHAIN_MARKER in text:
        preserved = hook.with_name(PRESERVED_HOOK)
        if not preserved.is_file():
            raise RuntimeError(f"Cannot restore missing original hook: {preserved}")
        shutil.move(str(preserved), str(hook))
        return hook, True
    start = text.find(HOOK_BEGIN)
    end = text.find(HOOK_END)
    if start < 0 or end < start:
        return hook, False
    end += len(HOOK_END)
    remaining = (text[:start].rstrip() + "\n" + text[end:].lstrip()).strip()
    if remaining in {
        "#!/bin/sh",
        "#!/bin/sh\nset -eu",
        "#!/usr/bin/env sh",
        "#!/usr/bin/env bash",
    }:
        hook.unlink(missing_ok=True)
    else:
        hook.write_text(remaining + "\n", encoding="utf-8")
        hook.chmod(0o755)
    return hook, True


def cmd_init(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    ui = TerminalUI()
    ui.title("Project setup", version=__version__)
    path = repo / CONFIG_NAME
    if path.exists() and not args.force:
        ui.info(f"Configuration already exists  {path}")
    else:
        path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
        ui.success(f"Configuration created  {path}")

    (repo / STATE_DIR / "runs").mkdir(parents=True, exist_ok=True)
    _ensure_gitignore(repo)
    ui.success(f"Runtime state ready  {repo / STATE_DIR}")

    if not args.no_hook:
        try:
            hook, action = _install_hook(repo, force=False)
            ui.success(f"Pre-push hook {action}  {hook}")
        except RuntimeError as exc:
            ui.warning(f"Hook not installed: {exc}")
    ui.info("Next: agenticbughunter doctor")
    return 0


def _run(args: argparse.Namespace, gate: bool) -> int:
    repo = repo_root(args.repo)
    config_path = _config_path(repo, args.config)
    cfg = load_config(config_path)
    ui = TerminalUI.from_config(
        cfg, enabled=not args.json, color=False if args.plain else None
    )
    ui.set_context(
        cfg=cfg,
        config_path=config_path,
        active_env=_active_environment_overrides(),
        version=__version__,
    )
    result = SecureReviewPipeline(
        cfg, progress=ui.progress_event if not args.json else None
    ).run(repo, base=args.base, head=args.head)
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        ui.final_result(result)
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
        choices = (
            sorted((p for p in runs.glob("*") if p.is_dir()), reverse=True)
            if runs.is_dir()
            else []
        )
        if not choices:
            print("No AgenticBugHunter runs found.")
            return 1
        path = choices[0] / "result.json"
    if not path.is_file():
        print(f"Run result not found: {path}")
        return 1
    raw = json.loads(path.read_text(encoding="utf-8"))
    if args.json or raw.get("status") == "error":
        print(json.dumps(raw, ensure_ascii=False, indent=2))
        return 0
    result = PipelineResult(
        run_id=str(raw.get("run_id") or path.parent.name),
        status=str(raw.get("status") or "unknown"),
        findings=[Finding(**item) for item in raw.get("findings", [])],
        comments=list(raw.get("comments", [])),
        run_dir=str(raw.get("run_dir") or path.parent),
        stages=[StageResult(**item) for item in raw.get("stages", [])],
    )
    TerminalUI(color=False if args.plain else None).final_result(result)
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Serve the read-only local run dashboard."""
    repo = repo_root(args.repo)
    serve_dashboard(
        repo,
        host=args.host,
        port=args.port,
        open_browser=not args.no_open,
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    config_path = _config_path(repo, args.config)
    cfg = load_config(config_path)
    ui = TerminalUI.from_config(cfg, color=False if args.plain else None)
    ui.set_context(
        cfg=cfg,
        config_path=config_path,
        active_env=_active_environment_overrides(),
        version=__version__,
    )
    ui.title("Environment check", version=__version__)
    ui.success(f"Repository  {repo}")
    ui.success(f"Configuration  {config_path or 'built-in defaults'}")
    ui.success(f"LLM  {cfg.llm.model} @ {cfg.llm.base_url}")
    from .bm25 import DEFAULT_MODEL_DIR, SASTRetriever

    retriever = SASTRetriever(DEFAULT_MODEL_DIR)
    ui.success(
        "Local BM25  "
        f"{len(retriever.rules)} rules / {retriever.metadata.get('cwe_count')} CWEs"
    )
    try:
        base = resolve_default_base(repo, head=args.head)
        ui.success(f"Git review base  {base}")
    except GitError as exc:
        ui.warning(f"Git review base  {exc}")
    hook = _git_hooks_dir(repo) / "pre-push"
    managed = hook.is_file() and HOOK_BEGIN in hook.read_text(
        encoding="utf-8", errors="replace"
    )
    if managed:
        ui.success(f"Pre-push gate managed  {hook}")
    else:
        ui.warning("Pre-push gate not installed")
    ui.blank()
    if args.check_llm:
        from .llm import create_client, extract_json_value

        response = create_client(cfg.llm).chat(
            [
                {
                    "role": "system",
                    "content": 'Return exactly one JSON object: {"ok": true}',
                },
                {
                    "role": "user",
                    "content": "Check text JSON compatibility. Do not call any tools.",
                },
            ],
            metadata={"stage": "doctor"},
        )
        if extract_json_value(response.content) != {"ok": True}:
            raise RuntimeError(
                "LLM was reachable but failed the text JSON compatibility check"
            )
        ui.success(
            "LLM text JSON request succeeded (repository contents were not sent)"
        )
    else:
        ui.info(
            "Local checks complete. Endpoint not contacted; use doctor --check-llm to test it."
        )
    ui.success("Local setup checks complete")
    return 0


def _project_config_path(repo: Path, explicit: str | None) -> Path:
    selected = _config_path(repo, explicit)
    return selected if selected is not None else repo / CONFIG_NAME


def cmd_config_show(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    path = _config_path(repo, args.config)
    cfg = load_config(path)
    ui = TerminalUI.from_config(cfg, color=False if args.plain else None)
    ui.set_context(
        cfg=cfg,
        config_path=path,
        active_env=_active_environment_overrides(),
        version=__version__,
    )
    ui.config_summary(cfg, path=path)
    return 0


def cmd_config_get(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    cfg = load_config(_config_path(repo, args.config))
    value = get_config_value(cfg, args.key)
    if "api_key" in args.key:
        value = "***REDACTED***" if value else ""
    print(value)
    return 0


def cmd_config_set(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    path = _project_config_path(repo, args.config)
    value = set_config_value(path, args.key, args.value)
    ui = TerminalUI(color=False if args.plain else None)
    display_value = "***REDACTED***" if "api_key" in args.key and value else value
    ui.success(f"{args.key} = {display_value}")
    ui.info(f"Saved to {path}")
    return 0


def cmd_config_env(args: argparse.Namespace) -> int:
    ui = TerminalUI(color=False if args.plain else None)
    ui.title("Environment overrides", version=__version__)
    ui.info(
        "TOML is the normal project configuration; environment values are temporary overrides for CI/experiments."
    )
    ui.key_value("ABH_CONFIG", "select an alternate TOML file")
    ui.blank()
    for env_name, (section, field_name) in sorted(environment_overrides().items()):
        ui.key_value(env_name, f"{section}.{field_name}")
    ui.blank()
    ui.info(
        "OPENAI_BASE_URL, OPENAI_API_KEY and OPENAI_MODEL remain supported for compatibility."
    )
    return 0


def cmd_config_path(args: argparse.Namespace) -> int:
    repo = repo_root(args.repo)
    path = _config_path(repo, args.config)
    print(path if path is not None else "built-in defaults")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agenticbughunter",
        description="Project-local agentic secure-code-review Git gate",
    )
    parser.add_argument(
        "--version", action="version", version=f"AgenticBugHunter {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "init", help="Add AgenticBugHunter configuration/runtime state to a Git project"
    )
    p.add_argument("--repo", default=".")
    p.add_argument("--force", action="store_true", help="overwrite the project config")
    p.add_argument(
        "--no-hook",
        action="store_true",
        help="do not install the managed pre-push hook",
    )
    p.set_defaults(func=cmd_init)

    for name, gate in (("review", False), ("gate", True)):
        p = sub.add_parser(
            name,
            help="Run staged secure code review"
            + (" and fail on supported findings" if gate else ""),
        )
        p.add_argument("--repo", default=".")
        p.add_argument(
            "--base",
            default=None,
            help="Base Git ref; defaults to upstream/origin default branch/HEAD~1, never HEAD itself",
        )
        p.add_argument("--head", default="HEAD")
        p.add_argument("--config", default=None)
        p.add_argument(
            "--json", action="store_true", help="write only result JSON to stdout"
        )
        p.add_argument("--plain", action="store_true", help="disable terminal colours")
        p.set_defaults(func=lambda a, g=gate: _run(a, g))

    p = sub.add_parser(
        "install-hook", help="Install/update the managed project pre-push gate"
    )
    p.add_argument("--repo", default=".")
    p.add_argument(
        "--force",
        action="store_true",
        help="backup and replace an incompatible existing hook",
    )
    p.set_defaults(func=cmd_install_hook)

    p = sub.add_parser(
        "uninstall-hook", help="Remove only the AgenticBugHunter managed hook block"
    )
    p.add_argument("--repo", default=".")
    p.set_defaults(func=cmd_uninstall_hook)

    p = sub.add_parser("show-run", help="Show a saved run result")
    p.add_argument("--repo", default=".")
    p.add_argument("--json", action="store_true", help="print raw saved JSON")
    p.add_argument("--plain", action="store_true", help="disable terminal colours")
    p.add_argument("run_id", nargs="?")
    p.set_defaults(func=cmd_show_run)

    p = sub.add_parser(
        "dashboard", aliases=["ui"], help="Open the live local run dashboard"
    )
    p.add_argument("--repo", default=".")
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="listen address (default: local machine only)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8765,
        help="listen port; use 0 for an available port",
    )
    p.add_argument(
        "--no-open", action="store_true", help="do not open a browser automatically"
    )
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser(
        "doctor",
        help="Validate project/package configuration without running the LLM pipeline",
    )
    p.add_argument("--repo", default=".")
    p.add_argument("--config", default=None)
    p.add_argument("--head", default="HEAD")
    p.add_argument("--plain", action="store_true", help="disable terminal colours")
    p.add_argument(
        "--check-llm",
        action="store_true",
        help="send a small text JSON test to the configured model (may incur API cost)",
    )
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser(
        "config", help="Inspect or change AgenticBugHunter configuration"
    )
    config_sub = p.add_subparsers(dest="config_command", required=True)

    c = config_sub.add_parser("show", help="Show the effective configuration")
    c.add_argument("--repo", default=".")
    c.add_argument("--config", default=None)
    c.add_argument("--plain", action="store_true")
    c.set_defaults(func=cmd_config_show)

    c = config_sub.add_parser("get", help="Read one effective setting")
    c.add_argument("key", choices=known_config_keys())
    c.add_argument("--repo", default=".")
    c.add_argument("--config", default=None)
    c.set_defaults(func=cmd_config_get)

    c = config_sub.add_parser(
        "set", help="Update one project setting without hand-editing TOML"
    )
    c.add_argument("key", choices=known_config_keys())
    c.add_argument("value")
    c.add_argument("--repo", default=".")
    c.add_argument("--config", default=None)
    c.add_argument("--plain", action="store_true")
    c.set_defaults(func=cmd_config_set)

    c = config_sub.add_parser("path", help="Show the active TOML configuration path")
    c.add_argument("--repo", default=".")
    c.add_argument("--config", default=None)
    c.set_defaults(func=cmd_config_path)

    c = config_sub.add_parser("env", help="Show supported ABH_* environment overrides")
    c.add_argument("--plain", action="store_true")
    c.set_defaults(func=cmd_config_env)
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
        if getattr(args, "json", False):
            print((exc.run_dir / "result.json").read_text(encoding="utf-8"), end="")
            return 2
        print(f"AgenticBugHunter: {exc}", file=sys.stderr)
        print(f"Logs: {exc.run_dir}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"AgenticBugHunter: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
