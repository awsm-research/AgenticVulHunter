from __future__ import annotations

import importlib.resources as ir
import json
from functools import lru_cache


def prompt(name: str) -> str:
    """Load a bundled stage prompt."""
    return (ir.files("agenticbughunter") / "prompts" / name).read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def cwe_knowledge() -> dict[str, dict]:
    """Load only the CWE entries reachable from the bundled BM25 model."""
    path = (
        ir.files("agenticbughunter")
        / "bm25"
        / "files"
        / "stage2_5_model"
        / "cwe_knowledge.json"
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    values = raw.get("cwes", []) if isinstance(raw, dict) else []
    return {
        str(item.get("id") or "").upper(): item
        for item in values
        if isinstance(item, dict) and item.get("id")
    }
