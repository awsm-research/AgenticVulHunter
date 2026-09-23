"""Small terminal UI used while a review is running."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


_BANNER = r"""
    █████╗ ██╗   ██╗██╗  ██╗
   ██╔══██╗██║   ██║██║  ██║
   ███████║██║   ██║███████║
   ██╔══██║╚██╗ ██╔╝██╔══██║
   ██║  ██║ ╚████╔╝ ██║  ██║
   ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝
""".strip("\n")

_STAGE_LABELS = {
    1: "Candidate localisation",
    2: "Context enrichment",
    3: "CWE hypothesis generation",
    4: "Vulnerability validation",
}


class TerminalUI:
    """Render the AVH header and four pipeline stages without extra dependencies."""

    def __init__(self, *, threshold: float, model: str, endpoint: str):
        self.threshold = threshold
        self.model = model
        self.endpoint = endpoint
        self.repo = "-"
        self.review = "-"
        self.status = {index: "pending" for index in _STAGE_LABELS}
        self.duration = {}
        self._drawn_lines = 0
        self.enabled = sys.stdout.isatty()

    def _stage_line(self, index: int) -> str:
        state = self.status[index]
        symbol = {
            "pending": "○",
            "running": "●",
            "done": "✓",
            "failed": "✗",
        }.get(state, "○")
        suffix = state
        if index in self.duration and state == "done":
            suffix = f"done  {self.duration[index] / 1000:.1f}s"
        return f"│ {symbol} {index}/4  {_STAGE_LABELS[index]:<57} {suffix:>12} │"

    def _lines(self) -> list[str]:
        width = 88
        top = "╭" + "─" * (width - 2) + "╮"
        bottom = "╰" + "─" * (width - 2) + "╯"
        return [
            *_BANNER.splitlines(),
            "AGENTIC VUL HUNTER",
            "Four-stage secure code review",
            "",
            top,
            f"│ {'Secure review':<{width - 4}} │",
            f"│ Repository  {self.repo:<72} │"[:width-1] + "│",
            f"│ Review      {self.review:<72} │"[:width-1] + "│",
            f"│ Model       {self.model:<72} │"[:width-1] + "│",
            f"│ Endpoint    {self.endpoint:<72} │"[:width-1] + "│",
            f"│ Threshold   {self.threshold:<72.2f} │"[:width-1] + "│",
            bottom,
            top,
            f"│ {'Pipeline':<{width - 4}} │",
            *[self._stage_line(i) for i in range(1, 5)],
            bottom,
        ]

    def render(self) -> None:
        if not self.enabled:
            return
        lines = self._lines()
        if self._drawn_lines:
            sys.stdout.write(f"\x1b[{self._drawn_lines}F")
        for line in lines:
            sys.stdout.write("\x1b[2K" + line + "\n")
        sys.stdout.flush()
        self._drawn_lines = len(lines)

    def event(self, event: str, payload: dict[str, Any]) -> None:
        if event == "review_started":
            self.repo = str(Path(payload.get("repo", ".")))
            base = str(payload.get("base", ""))[:8]
            head = str(payload.get("head", ""))[:8]
            self.review = f"{base} → {head}"
        elif event == "stage_started":
            self.status[int(payload["index"])] = "running"
        elif event == "stage_completed":
            index = int(payload["index"])
            self.status[index] = "done"
            self.duration[index] = float(payload.get("duration_ms", 0.0))
        elif event == "stage_failed":
            self.status[int(payload["index"])] = "failed"
        self.render()

    def finish(self) -> None:
        if self.enabled:
            sys.stdout.write("\n")
            sys.stdout.flush()
