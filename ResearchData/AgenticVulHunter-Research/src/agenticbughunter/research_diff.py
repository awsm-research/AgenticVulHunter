from __future__ import annotations

import importlib.resources as ir
import re
from pathlib import Path


# SCRBench diff IDs are 40-character commit hashes
HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")

# Finds COMMIT_HASH from the SCRBench setup script
COMMIT_HASH_RE = re.compile(
    r"^\s*COMMIT_HASH\s*=\s*[\"']?([0-9a-fA-F]{40})[\"']?\s*$",
    re.MULTILINE,
)


def diff_id_from_setup_script(path: str | Path = "/workspace/setup_repo.sh") -> str:
    """Read the SCRBench task commit id from setup_repo.sh."""

    setup = Path(path)

    # Read the task setup script prepared by SCRBench
    text = setup.read_text(encoding="utf-8", errors="replace")

    match = COMMIT_HASH_RE.search(text)

    if not match:
        raise RuntimeError(f"COMMIT_HASH was not found in {setup}")

    # Normalize the commit hash before using it as the diff id
    value = match.group(1).lower()

    if not HEX40.fullmatch(value):
        raise RuntimeError(f"Invalid COMMIT_HASH in {setup}: {value!r}")

    return value


def _resource(kind: str, diff_id: str):
    """Get the bundled raw or annotated diff resource."""

    if kind not in {"raw", "annotated"}:
        raise ValueError("kind must be raw or annotated")

    value = str(diff_id).strip().lower()

    # Make sure the supplied diff id is a valid commit hash
    if not HEX40.fullmatch(value):
        raise ValueError(f"Invalid diff id: {diff_id!r}")

    # Build the path to the frozen diff stored inside the package
    return (
        ir.files("agenticbughunter")
        / "research_data"
        / "stage_1_annotated"
        / kind
        / f"{value}.diff"
    )


def load_bundled_diff(diff_id: str, kind: str = "annotated") -> str:
    """Load one of the 144 frozen Stage-1 diff artifacts bundled with the experiment."""

    path = _resource(kind, diff_id)

    if not path.is_file():
        raise FileNotFoundError(f"Bundled {kind} diff not found for {diff_id}")

    text = path.read_text(encoding="utf-8", errors="replace")

    # Prevent an empty diff from being used in the experiment
    if not text.strip():
        raise RuntimeError(f"Bundled {kind} diff is empty for {diff_id}")

    return text


def available_diff_ids() -> list[str]:
    """Return all bundled SCRBench diff ids."""

    root = (
        ir.files("agenticbughunter")
        / "research_data"
        / "stage_1_annotated"
        / "annotated"
    )

    # Each .diff filename is the SCRBench commit id
    return sorted(
        p.name[:-5]
        for p in root.iterdir()
        if p.name.endswith(".diff")
    )