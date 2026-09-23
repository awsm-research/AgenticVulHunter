from __future__ import annotations

import importlib.resources as ir
import json
from functools import lru_cache


def prompt(name: str) -> str:
    """Load one of the prompts bundled with AgenticVulHunter."""
    return (ir.files("agenticvulhunter") / "prompts" / name).read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def cwe_knowledge() -> dict[str, dict]:
    """Build the small CWE lookup directly from rules.json."""
    path = ir.files("agenticvulhunter") / "bm25" / "rules.json"
    rules = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, dict] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        cwe_id = str(rule.get("cwe_id") or "").upper()
        if not cwe_id:
            continue

        entry = result.setdefault(
            cwe_id,
            {
                "id": cwe_id,
                "name": str(rule.get("cwe_name") or ""),
                "description": "",
                "impact": "",
                "patterns": [],
                "detection_indicators": [],
                "remediation_steps": [],
                "related_cwes": [],
            },
        )

        description = str(rule.get("description") or "").strip()
        pattern = str(rule.get("pattern") or "").strip()
        remediation = str(rule.get("remediation") or "").strip()

        if description and not entry["description"]:
            entry["description"] = description
        if pattern and pattern not in entry["patterns"]:
            entry["patterns"].append(pattern)
        if remediation and remediation not in entry["remediation_steps"]:
            entry["remediation_steps"].append(remediation)

    return result
