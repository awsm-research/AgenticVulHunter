from __future__ import annotations

import contextlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


class GitError(RuntimeError):
    pass


def _run(repo: Path, *args: str, check: bool = True) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable was not found on PATH") from exc
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise GitError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def repo_root(path: str | Path = ".") -> Path:
    candidate = Path(path).expanduser().resolve()
    if not candidate.exists():
        raise GitError(f"Repository path does not exist: {candidate}")
    root = _run(candidate, "rev-parse", "--show-toplevel")
    return Path(root).resolve()


def resolve_ref(repo: Path, ref: str) -> str:
    value = _run(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if not value:
        raise GitError(f"Git ref does not resolve to a commit: {ref}")
    return value


def _valid_distinct_ref(repo: Path, ref: str, head_sha: str) -> bool:
    try:
        return resolve_ref(repo, ref) != head_sha
    except GitError:
        return False


def resolve_default_base(repo: Path, head: str = "HEAD") -> str:
    head_sha = resolve_ref(repo, head)
    candidates: list[str] = []

    upstream = _run(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}", check=False)
    if upstream:
        candidates.append(upstream)

    remote_head = _run(repo, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD", check=False)
    if remote_head:
        candidates.append(remote_head)

    candidates.extend(["origin/main", "origin/master", f"{head}~1"])
    seen: set[str] = set()
    for ref in candidates:
        if not ref or ref in seen:
            continue
        seen.add(ref)
        if _valid_distinct_ref(repo, ref, head_sha):
            return ref

    raise GitError(
        "Could not determine a safe base ref distinct from the head commit. "
        "Pass --base explicitly (for example --base origin/main)."
    )


def merge_base(repo: Path, base: str, head: str) -> str:
    """Return the old revision underlying the three-dot review diff."""
    return _run(repo, "merge-base", base, head)


def diff(repo: Path, base: str, head: str = "HEAD", unified: int = 20) -> str:
    base_sha = resolve_ref(repo, base)
    head_sha = resolve_ref(repo, head)
    if base_sha == head_sha:
        raise GitError(
            f"Refusing to review an identical base/head ({base} == {head}). "
            "Choose a base that predates the change."
        )
    return _run(
        repo,
        "-c", "core.quotepath=false",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        f"--unified={max(0, int(unified))}",
        f"{base_sha}...{head_sha}",
    )


@dataclass
class Workspace:
    root: Path
    source_repo: Path
    temporary: bool = False


@contextlib.contextmanager
def isolated_workspace(repo: Path, head: str, enabled: bool = True, keep: bool = False) -> Iterator[Workspace]:
    if not enabled:
        yield Workspace(repo, repo, False)
        return

    head_sha = resolve_ref(repo, head)
    temp_parent = Path(tempfile.mkdtemp(prefix="agenticbughunter-worktree-"))
    worktree = temp_parent / "repo"
    added = False
    try:
        _run(repo, "worktree", "add", "--detach", str(worktree), head_sha)
        added = True
        yield Workspace(worktree, repo, True)
    finally:
        if not keep:
            if added:
                subprocess.run(
                    ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            shutil.rmtree(temp_parent, ignore_errors=True)
