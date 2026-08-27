from __future__ import annotations

import json
import re
from dataclasses import fields
from pathlib import Path
from typing import Any

from .config import Config, load_config


_SECTION_TYPES = {
    "llm": Config().llm,
    "bm25": Config().bm25,
    "pipeline": Config().pipeline,
    "agents": Config().agents,
    "repository": Config().repository,
    "ui": Config().ui,
}


def known_config_keys() -> list[str]:
    keys: list[str] = []
    for section, instance in _SECTION_TYPES.items():
        keys.extend(f"{section}.{item.name}" for item in fields(instance))
    return keys


def get_config_value(cfg: Config, dotted_key: str) -> Any:
    section, field_name = _split_key(dotted_key)
    return getattr(getattr(cfg, section), field_name)


def set_config_value(path: Path, dotted_key: str, raw_value: str) -> Any:
    section, field_name = _split_key(dotted_key)
    default_value = getattr(_SECTION_TYPES[section], field_name)
    value = _coerce(raw_value, default_value)
    rendered = _toml_scalar(value)

    original = path.read_text(encoding="utf-8") if path.is_file() else ""
    updated = _replace_or_append(original, section, field_name, rendered)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated, encoding="utf-8")

    try:
        # Validate the complete project configuration after the edit.
        load_config(path)
    except Exception:
        if original:
            path.write_text(original, encoding="utf-8")
        else:
            path.unlink(missing_ok=True)
        raise
    return value


def _split_key(dotted_key: str) -> tuple[str, str]:
    if "." not in dotted_key:
        raise ValueError("Configuration key must use section.name, for example pipeline.confidence_threshold")
    section, field_name = dotted_key.split(".", 1)
    if section not in _SECTION_TYPES:
        raise ValueError(f"Unknown configuration section: {section}")
    valid = {item.name for item in fields(_SECTION_TYPES[section])}
    if field_name not in valid:
        raise ValueError(f"Unknown configuration key: {dotted_key}")
    return section, field_name


def _coerce(raw: str, default_value: Any) -> Any:
    if isinstance(default_value, bool):
        lowered = raw.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
        raise ValueError(f"Expected boolean value for configuration setting, got {raw!r}")
    if isinstance(default_value, int) and not isinstance(default_value, bool):
        return int(raw)
    if isinstance(default_value, float):
        return float(raw)
    return raw


def _toml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _replace_or_append(text: str, section: str, field_name: str, rendered: str) -> str:
    lines = text.splitlines()
    section_header = f"[{section}]"
    section_start: int | None = None
    section_end = len(lines)

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == section_header:
            section_start = index
            continue
        if section_start is not None and index > section_start and re.match(r"^\s*\[[^]]+\]\s*$", line):
            section_end = index
            break

    assignment = re.compile(rf"^(\s*){re.escape(field_name)}\s*=.*$")
    if section_start is not None:
        for index in range(section_start + 1, section_end):
            match = assignment.match(lines[index])
            if match:
                lines[index] = f"{match.group(1)}{field_name} = {rendered}"
                return "\n".join(lines).rstrip() + "\n"

        insertion = section_end
        while insertion > section_start + 1 and not lines[insertion - 1].strip():
            insertion -= 1
        lines.insert(insertion, f"{field_name} = {rendered}")
        return "\n".join(lines).rstrip() + "\n"

    if lines and lines[-1].strip():
        lines.append("")
    lines.extend([section_header, f"{field_name} = {rendered}"])
    return "\n".join(lines).rstrip() + "\n"
