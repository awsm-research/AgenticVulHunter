from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SECRET_KEYS = re.compile(
    r"(api[_-]?key|authorization|password|secret|^(?:access_|refresh_|id_|auth_)?token$)",
    re.IGNORECASE,
)


def _safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("***REDACTED***" if _SECRET_KEYS.search(str(k)) else _safe(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_safe(v) for v in value]
    return value


class RunLogger:
    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.run_dir / "events.jsonl"
        self.log_path = self.run_dir / "run.log"
        self.logger = logging.getLogger(f"agenticbughunter.{run_dir.name}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self.logger.handlers.clear()
        handler = logging.FileHandler(self.log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(handler)

    def info(self, message: str, **metadata: Any) -> None:
        self.logger.info(
            "%s %s",
            message,
            json.dumps(_safe(metadata), ensure_ascii=False) if metadata else "",
        )
        self.event("info", {"message": message, **metadata})

    def error(self, message: str, **metadata: Any) -> None:
        self.logger.error(
            "%s %s",
            message,
            json.dumps(_safe(metadata), ensure_ascii=False) if metadata else "",
        )
        self.event("error", {"message": message, **metadata})

    def event(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "type": event_type,
            "payload": _safe(payload),
        }
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def stage_dir(self, stage: str) -> Path:
        path = self.run_dir / stage
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_json(self, path: Path, value: Any) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(_safe(value), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def write_text(self, path: Path, value: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def close(self) -> None:
        for handler in list(self.logger.handlers):
            try:
                handler.flush()
                handler.close()
            finally:
                self.logger.removeHandler(handler)
