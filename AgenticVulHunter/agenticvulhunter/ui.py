"""Small terminal UI used while AgenticVulHunter is running a review."""

from __future__ import annotations

import sys
import textwrap
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
    """Show the AVH review information and live four-stage progress."""

    def __init__(self, *, threshold: float, model: str, endpoint: str):
        self.threshold = threshold
        self.model = model
        self.endpoint = endpoint
        self.repo = "-"
        self.review = "-"
        self.status = {index: "pending" for index in _STAGE_LABELS}
        self.duration: dict[int, float] = {}
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
            suffix = f"done · {self.duration[index] / 1000:.1f}s"

        return f"│  {symbol}  {index}/4  {_STAGE_LABELS[index]:<51} {suffix:>16}  │"

    def _row(self, label: str, value: str, width: int) -> str:
        text = f"{label:<11}{value}"
        return f"│  {text:<{width - 6}.{width - 6}}  │"

    def _lines(self) -> list[str]:
        width = 82
        top = "╭" + "─" * (width - 2) + "╮"
        middle = "├" + "─" * (width - 2) + "┤"
        bottom = "╰" + "─" * (width - 2) + "╯"

        return [
            *_BANNER.splitlines(),
            "AGENTIC VUL HUNTER",
            "Four-stage secure code review",
            "",
            top,
            f"│  {'Secure review':<{width - 6}}  │",
            middle,
            self._row("Repository", self.repo, width),
            self._row("Review", self.review, width),
            self._row("Model", self.model, width),
            self._row("Endpoint", self.endpoint, width),
            self._row("Threshold", f"{self.threshold:.2f}", width),
            bottom,
            top,
            f"│  {'Pipeline':<{width - 6}}  │",
            middle,
            *[self._stage_line(index) for index in range(1, 5)],
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

    def print_results(self, comments: list[dict[str, Any]]) -> None:
        """Print the final findings in a short readable format."""
        print(f"Review complete · threshold {self.threshold:.2f} · findings {len(comments)}")

        if not comments:
            print("No findings passed the threshold.")
            return

        for index, comment in enumerate(comments, start=1):
            filepath = comment.get("filepath", "-")
            line = comment.get("line_number", "-")
            score = float(comment.get("judge_final_score", 0.0))
            message = str(comment.get("review_comment", "")).strip()

            print()
            print(f"[{index}] {filepath}:{line}  score {score:.2f}")
            for wrapped in textwrap.wrap(message, width=76):
                print(f"    {wrapped}")
