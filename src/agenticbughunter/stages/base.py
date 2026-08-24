from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..models import StageResult
from ..runlog import RunLogger


@dataclass
class StageContext:
    logger: RunLogger


class Stage:
    name = "stage"

    def execute(self, value: Any) -> Any:
        raise NotImplementedError

    def timed_execute(self, value: Any) -> StageResult:
        started = time.monotonic()
        self._logger.info(f"START {self.name}")
        try:
            output = self.execute(value)
        except Exception as exc:
            self._logger.error(f"ERROR {self.name}", error_type=type(exc).__name__, error=str(exc))
            raise
        duration_ms = (time.monotonic() - started) * 1000.0
        self._logger.info(f"END {self.name}", duration_ms=duration_ms)
        return StageResult(self.name, output, duration_ms)
