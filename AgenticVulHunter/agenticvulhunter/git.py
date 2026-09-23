from __future__ import annotations

import subprocess
from pathlib import Path


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
    return Path(_run(candidate, "rev-parse", "--show-toplevel")).resolve()


def resolve_ref(repo: Path, ref: str) -> str:
    value = _run(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if not value:
        raise GitError(f"Git ref does not resolve to a commit: {ref}")
    return value


def resolve_default_base(repo: Path, head: str = "HEAD") -> str:
    head_sha = resolve_ref(repo, head)
    candidates: list[str] = []

    upstream = _run(
        repo,
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
        check=False,
    )
    if upstream:
        candidates.append(upstream)

    remote_head = _run(
        repo,
        "symbolic-ref",
        "--quiet",
        "--short",
        "refs/remotes/origin/HEAD",
        check=False,
    )
    if remote_head:
        candidates.append(remote_head)

    candidates.extend(["origin/main", "origin/master", f"{head}~1"])
    for ref in dict.fromkeys(candidates):
        try:
            if resolve_ref(repo, ref) != head_sha:
                return ref
        except GitError:
            continue

    raise GitError("Could not determine the base ref. Pass --base explicitly.")


def merge_base(repo: Path, base: str, head: str) -> str:
    return _run(repo, "merge-base", base, head)


def diff(repo: Path, base: str, head: str = "HEAD", unified: int = 20) -> str:
    base_sha = resolve_ref(repo, base)
    head_sha = resolve_ref(repo, head)
    if base_sha == head_sha:
        raise GitError(f"Base and head are the same commit: {base} == {head}")

    return _run(
        repo,
        "-c",
        "core.quotepath=false",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--no-color",
        f"--unified={max(0, int(unified))}",
        f"{base_sha}...{head_sha}",
    )
