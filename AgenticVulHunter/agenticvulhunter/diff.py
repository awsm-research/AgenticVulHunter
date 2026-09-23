from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass


# Match a Git diff hunk header such as: @@ -10,5 +12,7 @@
# It captures where the changed block starts in the old file and the new file,
# along with the number of lines included in each side of the diff.
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class DiffLine:
    """Stores one line from a parsed diff."""

    filepath: str
    old_line: int | None
    new_line: int | None
    kind: str  # A = added, D = deleted, C = context
    text: str


def _decode_git_path(raw: str) -> str:
    """Convert a Git diff path into a normal repository path."""

    value = raw.strip()

    if value == "/dev/null":
        return value

    # Git may quote paths containing tabs, quotes or non-ASCII characters
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            value = ast.literal_eval(value)

            # Convert Git byte escapes back to UTF-8 when possible
            try:
                value = value.encode("latin-1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                pass

        except Exception:
            value = value[1:-1]

    return value.removeprefix("a/").removeprefix("b/")


def _header_path(line: str, prefix: str) -> str:
    """Read a filepath from a diff header."""

    value = line[len(prefix) :]

    # Traditional diff headers can include a timestamp after a tab
    value = value.split("\t", 1)[0]

    return _decode_git_path(value)


def parse_unified_diff(text: str) -> list[DiffLine]:
    """Parse a unified Git diff into DiffLine objects."""

    result: list[DiffLine] = []
    current_file = ""
    old_path = ""
    new_path = ""
    old_no: int | None = None
    new_no: int | None = None

    for line in text.splitlines():

        # Start of a new file
        if line.startswith("diff --git "):
            current_file = ""
            old_path = ""
            new_path = ""
            old_no = None
            new_no = None
            continue

        if line.startswith("--- "):
            old_path = _header_path(line, "--- ")

            if old_path != "/dev/null":
                current_file = old_path

            continue

        if line.startswith("+++ "):
            new_path = _header_path(line, "+++ ")

            if new_path != "/dev/null":
                current_file = new_path
            elif old_path and old_path != "/dev/null":
                current_file = old_path

            continue

        # Read the starting line numbers from the hunk
        m = _HUNK.match(line)

        if m:
            old_no = int(m.group(1))
            new_no = int(m.group(3))
            continue

        if old_no is None or new_no is None or not current_file:
            continue

        # Added line
        if line.startswith("+") and not line.startswith("+++"):
            result.append(
                DiffLine(current_file, None, new_no, "A", line[1:])
            )
            new_no += 1

        # Deleted line
        elif line.startswith("-") and not line.startswith("---"):
            result.append(
                DiffLine(current_file, old_no, None, "D", line[1:])
            )
            old_no += 1

        # Unchanged context line
        elif line.startswith(" "):
            result.append(
                DiffLine(current_file, old_no, new_no, "C", line[1:])
            )
            old_no += 1
            new_no += 1

        elif line.startswith("\\ No newline"):
            continue

    return result


def changed_line_map(
    lines: Iterable[DiffLine],
) -> dict[tuple[str, int, str], str]:
    """Create a lookup for added and deleted lines."""

    out: dict[tuple[str, int, str], str] = {}

    for line in lines:
        if line.kind == "A" and line.new_line is not None:
            out[
                (line.filepath, int(line.new_line), "A")
            ] = line.text

        elif line.kind == "D" and line.old_line is not None:
            out[
                (line.filepath, int(line.old_line), "D")
            ] = line.text

    return out


def added_line_map(
    lines: Iterable[DiffLine],
) -> dict[tuple[str, int], str]:
    """Create a lookup containing only added lines."""

    # Backwards-compatible helper used by older integrations/tests
    return {
        (line.filepath, int(line.new_line)): line.text
        for line in lines
        if line.kind == "A" and line.new_line is not None
    }


def annotate_diff(text: str) -> str:
    """Convert a Git diff into the [A,D,C] representation used by Stage 1."""

    lines = parse_unified_diff(text)
    out: list[str] = []
    last_file = None

    for line in lines:

        # Add a heading when moving to another file
        if line.filepath != last_file:
            out.append(f"\n### FILE {line.filepath}")
            last_file = line.filepath

        number = (
            line.new_line
            if line.kind != "D"
            else line.old_line
        )

        out.append(
            f"[{line.kind},{line.filepath},{number}] {line.text}"
        )

    return ("\n".join(out).strip() + "\n") if out else ""


def parse_annotated_diff(text: str) -> list[DiffLine]:
    """Parse the frozen Stage-1 [A,D,C] representation used by the paper harness.

    Input records look like::

        [A,src/app.py,42] dangerous_call(value)
        [D,src/app.py,41] old_guard(value)
        [C,src/app.py,43] return result

    Hunk headers and any non-record lines are ignored. The filepath is split
    from the line number using rsplit so repository paths containing commas
    remain valid.
    """

    result: list[DiffLine] = []

    for raw in text.splitlines():

        if not raw.startswith("["):
            continue

        close = raw.find("]")

        if close <= 3:
            continue

        marker = raw[1:close]

        try:
            kind, payload = marker.split(",", 1)
            filepath, line_text = payload.rsplit(",", 1)
            number = int(line_text)

        except (ValueError, TypeError):
            continue

        kind = kind.strip().upper()

        if kind not in {"A", "D", "C"} or number < 1:
            continue

        filepath = filepath.rstrip("\t")
        statement = raw[close + 1 :].lstrip()

        if kind == "A":
            result.append(
                DiffLine(filepath, None, number, "A", statement)
            )

        elif kind == "D":
            result.append(
                DiffLine(filepath, number, None, "D", statement)
            )

        else:
            # Context lines are only used as surrounding evidence in Stage 1
            result.append(
                DiffLine(filepath, number, number, "C", statement)
            )

    return result