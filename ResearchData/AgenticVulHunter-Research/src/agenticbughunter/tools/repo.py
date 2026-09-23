from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from ..config import RepositoryConfig
from ..llm.agent import Tool, ToolRegistry


class RepositoryTools:
    """Read-only repository tools intentionally narrower than a shell."""

    def __init__(
        self,
        root: Path,
        config: RepositoryConfig,
        *,
        base_ref: str | None = None,
        use_git_index: bool = True,
    ):
        self.root = root.resolve()
        self.config = config
        self.base_ref = base_ref
        self.use_git_index = use_git_index

    def _workspace_files(self) -> list[Path]:
        """List current workspace files without consulting Git."""
        excluded = {".git", ".agenticbughunter"}
        return sorted(
            path
            for path in self.root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and not excluded.intersection(path.relative_to(self.root).parts)
        )

    @staticmethod
    def _clean_relative(relative: str) -> str:
        clean = str(relative or "").replace("\\", "/").strip()
        if not clean:
            raise ValueError("path is required")
        path = PurePosixPath(clean)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Path escapes repository root")
        return str(path)

    def _path(self, relative: str) -> Path:
        clean = self._clean_relative(relative)
        path = (self.root / clean).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError("Path escapes repository root")
        return path

    def _bounded_lines(
        self, text: str, rel: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        start = max(1, int(args.get("start_line") or 1))
        requested_end = int(
            args.get("end_line") or (start + self.config.max_read_lines - 1)
        )
        end = min(requested_end, start + self.config.max_read_lines - 1)
        lines = text.splitlines()
        end = min(end, len(lines))
        selected = (
            [f"{i}: {lines[i - 1]}" for i in range(start, end + 1)]
            if start <= end
            else []
        )
        return {
            "path": rel,
            "start_line": start,
            "end_line": end,
            "text": "\n".join(selected),
        }

    def read_file(self, args: dict[str, Any]) -> dict[str, Any]:
        rel = self._clean_relative(str(args.get("path") or ""))
        path = self._path(rel)
        if not path.is_file():
            raise FileNotFoundError(rel)
        return self._bounded_lines(
            path.read_text(encoding="utf-8", errors="replace"), rel, args
        )

    def read_base_file(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.base_ref:
            raise RuntimeError("No base revision is configured for this run")
        rel = self._clean_relative(str(args.get("path") or ""))
        result = subprocess.run(
            ["git", "-C", str(self.root), "show", f"{self.base_ref}:{rel}"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise FileNotFoundError(f"{rel} at base revision {self.base_ref}")
        return self._bounded_lines(result.stdout, rel, args)

    def file_context(self, args: dict[str, Any]) -> dict[str, Any]:
        line = int(args.get("line") or 0)
        if line < 1:
            raise ValueError("line must be >= 1")
        radius = min(
            max(1, int(args.get("radius") or self.config.context_radius)),
            self.config.context_radius,
            (self.config.max_read_lines - 1) // 2,
        )
        payload = {
            "path": args.get("path"),
            "start_line": max(1, line - radius),
            "end_line": line + radius,
        }
        if str(args.get("revision") or "head").lower() == "base":
            return self.read_base_file(payload)
        return self.read_file(payload)

    def search_code(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query") or "")
        if not query:
            raise ValueError("query is required")
        path = str(args.get("path") or "")
        if path:
            path = self._clean_relative(path)
        max_results = min(
            max(1, int(args.get("max_results") or self.config.max_search_results)),
            self.config.max_search_results,
        )
        if self.use_git_index:
            command = ["git", "-C", str(self.root), "grep", "-n", "-F", "-e", query]
            if path:
                command += ["--", path]
            result = subprocess.run(
                command, text=True, capture_output=True, check=False
            )
            if result.returncode not in (0, 1):
                raise RuntimeError(result.stderr.strip() or "git grep failed")
            all_lines = result.stdout.splitlines()
        else:
            scope = self._path(path) if path else self.root
            files = (
                [scope]
                if scope.is_file()
                else [p for p in self._workspace_files() if scope in p.parents]
            )
            all_lines = []
            for candidate in files:
                relative = candidate.relative_to(self.root).as_posix()
                for number, line in enumerate(
                    candidate.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines(),
                    1,
                ):
                    if query in line:
                        all_lines.append(f"{relative}:{number}:{line}")
        return {
            "query": query,
            "path": path,
            "matches": all_lines[:max_results],
            "truncated": len(all_lines) > max_results,
        }

    def list_files(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = str(args.get("pattern") or "*")
        if self.use_git_index:
            result = subprocess.run(
                ["git", "-C", str(self.root), "ls-files"],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "git ls-files failed")
            candidates = result.stdout.splitlines()
        else:
            candidates = [
                p.relative_to(self.root).as_posix() for p in self._workspace_files()
            ]
        values = [p for p in candidates if fnmatch.fnmatch(p, pattern)]
        limit = min(max(1, int(args.get("limit") or 100)), 300)
        return {
            "pattern": pattern,
            "files": values[:limit],
            "truncated": len(values) > limit,
        }

    def registry(self, include_list: bool = True) -> ToolRegistry:
        tools = [
            Tool(
                "read_file",
                "Read a bounded line range from the current repository workspace.",
                {
                    "path": "repository-relative path",
                    "start_line": "optional integer",
                    "end_line": "optional integer",
                },
                self.read_file,
            ),
            Tool(
                "file_context",
                "Read code around a line. Use revision=base for a deleted line/control removed by the patch.",
                {
                    "path": "repository-relative path",
                    "line": "integer",
                    "radius": "optional integer",
                    "revision": "head|base",
                },
                self.file_context,
            ),
            Tool(
                "search_code",
                "Exact fixed-string search across current workspace files; optionally scope to a path.",
                {
                    "query": "exact string or symbol",
                    "path": "optional file/directory",
                    "max_results": "optional integer",
                },
                self.search_code,
            ),
        ]
        if self.base_ref:
            tools.append(
                Tool(
                    "read_base_file",
                    "Read a bounded line range from the base revision. Useful for deleted code/security controls.",
                    {
                        "path": "repository-relative path",
                        "start_line": "optional integer",
                        "end_line": "optional integer",
                    },
                    self.read_base_file,
                )
            )
        if include_list:
            tools.append(
                Tool(
                    "list_files",
                    "List current workspace files matching a glob pattern.",
                    {"pattern": "glob such as **/*.py", "limit": "optional integer"},
                    self.list_files,
                )
            )
        return ToolRegistry(tools)
