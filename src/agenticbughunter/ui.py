from __future__ import annotations

import os
import shutil
import sys
import textwrap
from dataclasses import asdict
from pathlib import Path
from typing import Any, TextIO

from .config import Config, environment_overrides
from .models import PipelineResult, StageResult

_STAGE_LABELS = {
    "stage1_candidates": "Candidate localisation",
    "stage2_context": "Context enrichment",
    "stage3_hypotheses": "CWE hypothesis generation",
    "stage4_judge": "Vulnerability validation",
    "stage5_filter": "Finding filter & review comments",
}
_STAGE_INDEX = {name: idx for idx, name in enumerate(_STAGE_LABELS, start=1)}

_LOGO = (
    " █████╗ ██████╗ ██╗  ██╗",
    "██╔══██╗██╔══██╗██║  ██║",
    "███████║██████╔╝███████║",
    "██╔══██║██╔══██╗██╔══██║",
    "██║  ██║██████╔╝██║  ██║",
    "╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝",
)


class TerminalUI:
    """Dependency-free presentation layer for AgenticBugHunter.

    All methods are intentionally presentation-only. Pipeline behaviour and
    security decisions remain outside this class.
    """

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        enabled: bool = True,
        color: bool | None = None,
        banner: bool = True,
        live_progress: bool = True,
        show_config: bool = True,
        show_stage_details: bool = True,
    ):
        self.stream = stream or sys.stdout
        self.enabled = enabled
        self.interactive = (
            bool(getattr(self.stream, "isatty", lambda: False)())
            and os.getenv("TERM", "") != "dumb"
        )
        if color is None:
            color = self.interactive and "NO_COLOR" not in os.environ
        self.color = bool(color)
        self.banner = bool(banner)
        self.live_progress = bool(live_progress) and self.interactive
        self.show_config = bool(show_config)
        self.show_stage_details = bool(show_stage_details)
        self.width = max(60, shutil.get_terminal_size((100, 24)).columns)

        self.config_path: Path | None = None
        self.active_env: list[str] = []
        self.version: str | None = None
        self.cfg: Config | None = None

        self._active_stage: str | None = None
        self._stage_state: dict[str, dict[str, Any]] = {
            name: {"status": "pending", "duration_ms": 0.0, "detail": "", "error": ""}
            for name in _STAGE_LABELS
        }
        self._live_lines = 0

    @classmethod
    def from_config(
        cls,
        cfg: Config,
        *,
        stream: TextIO | None = None,
        enabled: bool = True,
        color: bool | None = None,
    ) -> TerminalUI:
        return cls(
            stream=stream,
            enabled=enabled,
            color=color,
            banner=cfg.ui.banner,
            live_progress=cfg.ui.live_progress,
            show_config=cfg.ui.show_config,
            show_stage_details=cfg.ui.show_stage_details,
        )

    def set_context(
        self,
        *,
        cfg: Config | None = None,
        config_path: Path | None = None,
        active_env: list[str] | None = None,
        version: str | None = None,
    ) -> None:
        self.cfg = cfg
        self.config_path = config_path
        self.active_env = list(active_env or [])
        self.version = version

    def _paint(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def _write(self, text: str = "") -> None:
        if self.enabled:
            print(text, file=self.stream, flush=True)

    def _brand(
        self, subtitle: str | None = None, *, version: str | None = None
    ) -> None:
        version = version or self.version
        if self.banner and self.interactive and self.width >= 72:
            for line in _LOGO:
                self._write(self._paint(line, "1;36"))
            name = "AGENTIC BUG HUNTER"
            if version:
                name += f"  v{version}"
            self._write(self._paint(name, "1;35"))
        else:
            name = "AgenticBugHunter"
            if version:
                name += f" v{version}"
            self._write(self._paint(name, "1;36"))
        if subtitle:
            self._write(self._paint(subtitle, "2"))
        self._write()

    def title(self, subtitle: str | None = None, *, version: str | None = None) -> None:
        self._brand(subtitle, version=version)

    def blank(self) -> None:
        self._write()

    def key_value(self, key: str, value: Any) -> None:
        self._write(f"  {self._paint(key.ljust(18), '2')} {value}")

    def success(self, message: str) -> None:
        self._write(f"  {self._paint('✓', '32')} {message}")

    def warning(self, message: str) -> None:
        self._write(f"  {self._paint('!', '33')} {message}")

    def error(self, message: str) -> None:
        self._write(f"  {self._paint('✗', '31')} {message}")

    def info(self, message: str) -> None:
        self._write(f"  {self._paint('•', '36')} {message}")

    def panel(self, title: str, rows: list[tuple[str, Any]]) -> None:
        if not self.enabled:
            return
        max_width = min(100, max(60, self.width - 2))
        rendered = [f"{key:<11} {value}" for key, value in rows]
        content_width = min(
            max_width - 4, max([len(title) + 4, *(len(x) for x in rendered)])
        )
        top_fill = max(1, content_width - len(title) - 1)
        self._write(self._paint(f"╭─ {title} " + "─" * top_fill + "╮", "2"))
        for row in rendered:
            clipped = (
                row
                if len(row) <= content_width
                else row[: max(1, content_width - 1)] + "…"
            )
            self._write(
                self._paint("│", "2")
                + " "
                + clipped.ljust(content_width)
                + " "
                + self._paint("│", "2")
            )
        self._write(self._paint("╰" + "─" * (content_width + 2) + "╯", "2"))

    def _run_panel(self, payload: dict[str, Any]) -> None:
        repo = str(payload.get("repo", ""))
        cfg = self.cfg
        rows: list[tuple[str, Any]] = [
            ("Repository", repo),
            ("Review", f"{payload.get('base', '')} → {payload.get('head', '')}"),
            ("Model", payload.get("model", "")),
        ]
        if self.show_config:
            rows.append(
                (
                    "TOML",
                    str(self.config_path) if self.config_path else "built-in defaults",
                )
            )
        if cfg is not None:
            rows.append(
                (
                    "Policy",
                    f"threshold {cfg.pipeline.confidence_threshold:.2f}  ·  candidates {cfg.pipeline.max_candidates}"
                    f"  ·  BM25 top-k {cfg.bm25.top_k}",
                )
            )
        else:
            rows.append(("Threshold", f"{float(payload.get('threshold', 0.0)):.2f}"))
        if self.active_env:
            rows.append(
                ("Overrides", f"{len(self.active_env)} environment override(s) active")
            )
        self.panel("Secure review", rows)
        self._write()

    def _pipeline_box_lines(self) -> list[str]:
        width = min(98, max(58, self.width - 2))
        inner = width - 2
        title = " Pipeline "
        lines = ["╭" + title + "─" * max(0, inner - len(title)) + "╮"]
        for name, label in _STAGE_LABELS.items():
            state = self._stage_state[name]
            status = state["status"]
            idx = _STAGE_INDEX[name]
            symbol = {"pending": "○", "running": "◐", "done": "✓", "failed": "✗"}.get(
                status, "○"
            )
            right = "pending"
            if status == "running":
                right = "running"
            elif status == "done":
                duration = _format_duration(float(state["duration_ms"]))
                detail = (
                    str(state.get("detail") or "") if self.show_stage_details else ""
                )
                right = f"{duration}" + (f" · {detail}" if detail else "")
            elif status == "failed":
                right = "failed"
            left = f" {symbol} {idx}/5  {label}"
            if len(left) + len(right) + 2 > inner:
                keep = max(8, inner - len(left) - 3)
                right = (right[: keep - 1] + "…") if len(right) > keep else right
            gap = max(1, inner - len(left) - len(right) - 1)
            content = (left + " " * gap + right + " ")[:inner].ljust(inner)
            lines.append("│" + content + "│")
        lines.append("╰" + "─" * inner + "╯")
        return lines

    def _color_pipeline_line(self, line: str) -> str:
        if "✓" in line:
            return line.replace("✓", self._paint("✓", "32"), 1)
        if "✗" in line:
            return line.replace("✗", self._paint("✗", "31"), 1)
        if "◐" in line:
            return line.replace("◐", self._paint("◐", "36"), 1).replace(
                "running", self._paint("running", "1;36"), 1
            )
        if "○" in line:
            return line.replace("○", self._paint("○", "2"), 1).replace(
                "pending", self._paint("pending", "2"), 1
            )
        return self._paint(line, "2")

    def _render_live_pipeline(self) -> None:
        if not (self.enabled and self.live_progress):
            return
        lines = self._pipeline_box_lines()
        if self._live_lines:
            self.stream.write(f"\033[{self._live_lines}A")
        for line in lines:
            self.stream.write("\033[2K\r" + self._color_pipeline_line(line) + "\n")
        self.stream.flush()
        self._live_lines = len(lines)

    def progress_event(self, event: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        if event == "pipeline_started":
            self._brand("Staged secure code review")
            self._run_panel(payload)
            if self.live_progress:
                self._render_live_pipeline()
            else:
                self._write(self._paint("Pipeline", "1"))
            return

        if event == "workspace_ready":
            if payload.get("isolated") and not self.live_progress:
                self.info("Isolated review workspace ready")
            return

        if event == "stage_started":
            name = str(payload.get("stage") or "")
            self._active_stage = name
            if name in self._stage_state:
                self._stage_state[name]["status"] = "running"
            if self.live_progress:
                self._render_live_pipeline()
                return
            idx = _STAGE_INDEX.get(name, payload.get("index", "?"))
            label = _STAGE_LABELS.get(name, name.replace("_", " ").title())
            self._write(f"  {self._paint('○', '36')} {idx}/5  {label}")
            return

        if event == "stage_completed":
            name = str(payload.get("stage") or "")
            idx = _STAGE_INDEX.get(name, payload.get("index", "?"))
            label = _STAGE_LABELS.get(name, name.replace("_", " ").title())
            duration_ms = float(payload.get("duration_ms", 0.0))
            detail = stage_output_summary(
                StageResult(name, payload.get("output"), duration_ms)
            )
            if name in self._stage_state:
                self._stage_state[name].update(
                    status="done", duration_ms=duration_ms, detail=detail
                )
            if self.live_progress:
                self._render_live_pipeline()
            else:
                suffix = f"  {self._paint(_format_duration(duration_ms), '2')}"
                if detail and self.show_stage_details:
                    suffix += f"  {self._paint(detail, '2')}"
                self._write(f"  {self._paint('✓', '32')} {idx}/5  {label}{suffix}")
            self._active_stage = None
            return

        if event == "stage_failed":
            name = str(payload.get("stage") or self._active_stage or "stage")
            idx = _STAGE_INDEX.get(name, payload.get("index", "?"))
            label = _STAGE_LABELS.get(name, name.replace("_", " ").title())
            if name in self._stage_state:
                self._stage_state[name].update(
                    status="failed", error=str(payload.get("error", ""))
                )
            if self.live_progress:
                self._render_live_pipeline()
                self._write()
                self.error(str(payload.get("error", "")))
            else:
                self._write(
                    f"  {self._paint('✗', '31')} {idx}/5  {label}  {payload.get('error', '')}"
                )
            self._active_stage = None
            return

        if event == "empty_diff":
            self.success("No changed lines to review")

    def final_result(self, result: PipelineResult) -> None:
        self._write()
        self._write(self._paint("Review result", "1"))
        if result.status == "pass":
            self.success(f"PASS  {len(result.findings)} supported finding(s)")
        elif result.status == "block":
            self.error(f"BLOCK  {len(result.findings)} supported finding(s)")
        else:
            self.warning(result.status.upper())

        if result.stages:
            total = sum(stage.duration_ms for stage in result.stages)
            self.key_value("stage time", _format_duration(total))
        self.key_value("run", result.run_id)
        self.key_value("artifacts", result.run_dir)

        if not result.findings:
            self._write()
            self._write(
                self._paint(
                    "No supported vulnerabilities passed the configured threshold.", "2"
                )
            )
            return

        self._write()
        self._write(self._paint("Findings", "1"))
        for index, finding in enumerate(result.findings, start=1):
            change_type = str(finding.assessment.get("change_type") or "A")
            change_label = {"A": "added", "D": "deleted"}.get(change_type, change_type)
            cwe_name = f" — {finding.cwe_name}" if finding.cwe_name else ""
            self._write(
                f"  {self._paint(str(index) + '.', '1')} "
                f"{self._paint(finding.cwe_id, '33')}{cwe_name}  "
                f"score={finding.final_score:.3f}"
            )
            self._write(
                f"     {finding.filepath}:{finding.changed_line}  {change_label}"
            )
            statement = " ".join(finding.statement.split())
            if statement:
                self._write(f"     code: {statement[:140]}")
            comment = " ".join(finding.review_comment.split())
            if comment:
                for line in textwrap.wrap(
                    comment, width=96, subsequent_indent="       "
                ):
                    self._write(f"     {line}")

    def config_summary(self, cfg: Config, *, path: Path | None = None) -> None:
        self.title("Effective TOML configuration")
        self.panel(
            "Configuration source",
            [
                ("TOML", str(path) if path else "built-in defaults"),
                ("Precedence", "environment overrides → TOML → defaults"),
                (
                    "Overrides",
                    f"{len(_active_config_env())} active"
                    if _active_config_env()
                    else "none",
                ),
            ],
        )
        raw = asdict(cfg)
        env_by_key = _env_by_config_key()
        for section, values in raw.items():
            self._write()
            self._write(self._paint(f"[{section}]", "1"))
            for key, value in values.items():
                if "api_key" in key:
                    value = "***REDACTED***" if value else ""
                source = env_by_key.get(f"{section}.{key}")
                suffix = (
                    f"  {self._paint('← ' + source, '33')}"
                    if source and source in os.environ
                    else ""
                )
                self.key_value(key, f"{value}{suffix}")


def _active_config_env() -> list[str]:
    names = [name for name in environment_overrides() if name in os.environ]
    for legacy in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL"):
        if legacy in os.environ:
            names.append(legacy)
    return sorted(set(names))


def _env_by_config_key() -> dict[str, str]:
    mapping = {
        f"{section}.{field}": env
        for env, (section, field) in environment_overrides().items()
    }
    mapping.update(
        {
            "llm.base_url": "OPENAI_BASE_URL"
            if "OPENAI_BASE_URL" in os.environ
            else mapping.get("llm.base_url", ""),
            "llm.api_key": "OPENAI_API_KEY"
            if "OPENAI_API_KEY" in os.environ
            else mapping.get("llm.api_key", ""),
            "llm.model": "OPENAI_MODEL"
            if "OPENAI_MODEL" in os.environ
            else mapping.get("llm.model", ""),
        }
    )
    return mapping


def stage_output_summary(stage: StageResult) -> str:
    output = stage.output
    if stage.name == "stage1_candidates" and isinstance(output, list):
        return f"{len(output)} candidate(s)"
    if stage.name == "stage2_context" and isinstance(output, list):
        return f"{len(output)} candidate(s) enriched"
    if stage.name == "stage3_hypotheses" and isinstance(output, list):
        hypotheses = sum(
            len(item.get("hypotheses", [])) for item in output if isinstance(item, dict)
        )
        return f"{hypotheses} hypotheses"
    if stage.name == "stage4_judge" and isinstance(output, list):
        assessments = sum(
            len(item.get("cwe_assessments", []))
            for item in output
            if isinstance(item, dict)
        )
        supported = sum(
            1
            for item in output
            if isinstance(item, dict)
            for assessment in item.get("cwe_assessments", [])
            if isinstance(assessment, dict) and assessment.get("verdict") == "supported"
        )
        return f"{assessments} assessed, {supported} supported"
    if stage.name == "stage5_filter" and isinstance(output, dict):
        return f"{len(output.get('findings', []))} final finding(s)"
    return ""


def _format_duration(duration_ms: float) -> str:
    seconds = max(0.0, duration_ms / 1000.0)
    if seconds < 1:
        return f"{duration_ms:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(seconds, 60)
    return f"{int(minutes)}m {remainder:.0f}s"
