from __future__ import annotations

import importlib.resources as ir
import json
from functools import lru_cache


def prompt(name: str) -> str:
    return (ir.files("agenticbughunter") / "prompts" / name).read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def cwe_knowledge() -> dict[str, dict]:
    values: list[dict] = []
    for name in ("cwe.json", "cwe_missing.json"):
        raw = json.loads((ir.files("agenticbughunter") / "memory" / name).read_text(encoding="utf-8"))
        if isinstance(raw, list):
            values.extend(x for x in raw if isinstance(x, dict))
        elif isinstance(raw, dict):
            if isinstance(raw.get("entries"), list):
                values.extend(x for x in raw["entries"] if isinstance(x, dict))
            elif isinstance(raw.get("cwes"), list):
                values.extend(x for x in raw["cwes"] if isinstance(x, dict))
            else:
                values.extend(x for x in raw.values() if isinstance(x, dict))

    out: dict[str, dict] = {}
    for item in values:
        raw_id = str(item.get("cwe_id") or item.get("id") or item.get("CWE-ID") or "").upper().strip()
        if raw_id and not raw_id.startswith("CWE-") and raw_id.isdigit():
            raw_id = f"CWE-{raw_id}"
        if raw_id:
            out[raw_id] = item
    return out
