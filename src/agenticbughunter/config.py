from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass
class LLMConfig:
    base_url: str = "http://localhost:11434/v1"
    api_key: str = "ollama"
    model: str = "qwen3-coder:30b"
    timeout_seconds: float = 300.0
    max_tokens: int = 6000
    temperature: float = 0.0


@dataclass
class BM25Config:
    top_k: int = 10
    max_requests_per_candidate: int = 4


@dataclass
class PipelineConfig:
    max_candidates: int = 5
    max_hypotheses: int = 5
    confidence_threshold: float = 0.75
    max_comments: int = 5
    block_on_findings: bool = True
    isolate_worktree: bool = True
    keep_worktree: bool = False


@dataclass
class AgentConfig:
    stage1_max_steps: int = 30
    stage2_max_steps: int = 30
    stage3_max_steps: int = 30
    stage4_mode: str = "api"
    stage4_max_steps: int = 10


@dataclass
class RepositoryConfig:
    context_radius: int = 200
    max_read_lines: int = 300
    max_search_results: int = 30


@dataclass
class UIConfig:
    # Presentation-only settings. These never alter vulnerability analysis.
    banner: bool = True
    live_progress: bool = True
    show_config: bool = True
    show_stage_details: bool = True


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    bm25: BM25Config = field(default_factory=BM25Config)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)
    repository: RepositoryConfig = field(default_factory=RepositoryConfig)
    ui: UIConfig = field(default_factory=UIConfig)


_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "ABH_LLM_BASE_URL": ("llm", "base_url"),
    "ABH_LLM_API_KEY": ("llm", "api_key"),
    "ABH_LLM_MODEL": ("llm", "model"),
    "ABH_LLM_TIMEOUT_SECONDS": ("llm", "timeout_seconds"),
    "ABH_LLM_MAX_TOKENS": ("llm", "max_tokens"),
    "ABH_LLM_TEMPERATURE": ("llm", "temperature"),
    "ABH_BM25_TOP_K": ("bm25", "top_k"),
    "ABH_BM25_MAX_REQUESTS_PER_CANDIDATE": ("bm25", "max_requests_per_candidate"),
    "ABH_PIPELINE_MAX_CANDIDATES": ("pipeline", "max_candidates"),
    "ABH_PIPELINE_MAX_HYPOTHESES": ("pipeline", "max_hypotheses"),
    "ABH_PIPELINE_CONFIDENCE_THRESHOLD": ("pipeline", "confidence_threshold"),
    "ABH_PIPELINE_MAX_COMMENTS": ("pipeline", "max_comments"),
    "ABH_PIPELINE_BLOCK_ON_FINDINGS": ("pipeline", "block_on_findings"),
    "ABH_PIPELINE_ISOLATE_WORKTREE": ("pipeline", "isolate_worktree"),
    "ABH_PIPELINE_KEEP_WORKTREE": ("pipeline", "keep_worktree"),
    "ABH_AGENTS_STAGE1_MAX_STEPS": ("agents", "stage1_max_steps"),
    "ABH_AGENTS_STAGE2_MAX_STEPS": ("agents", "stage2_max_steps"),
    "ABH_AGENTS_STAGE3_MAX_STEPS": ("agents", "stage3_max_steps"),
    "ABH_AGENTS_STAGE4_MODE": ("agents", "stage4_mode"),
    "ABH_AGENTS_STAGE4_MAX_STEPS": ("agents", "stage4_max_steps"),
    "ABH_REPOSITORY_CONTEXT_RADIUS": ("repository", "context_radius"),
    "ABH_REPOSITORY_MAX_READ_LINES": ("repository", "max_read_lines"),
    "ABH_REPOSITORY_MAX_SEARCH_RESULTS": ("repository", "max_search_results"),
    "ABH_UI_BANNER": ("ui", "banner"),
    "ABH_UI_LIVE_PROGRESS": ("ui", "live_progress"),
    "ABH_UI_SHOW_CONFIG": ("ui", "show_config"),
    "ABH_UI_SHOW_STAGE_DETAILS": ("ui", "show_stage_details"),
}


def environment_overrides() -> dict[str, tuple[str, str]]:
    return dict(_ENV_OVERRIDES)


def _env_value(raw: str, current: Any) -> Any:
    if isinstance(current, bool):
        value = raw.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        raise ValueError(f"invalid boolean environment value: {raw!r}")
    if isinstance(current, int) and not isinstance(current, bool):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    return raw


def _apply_environment(cfg: Config) -> None:
    for env_name, (section, field_name) in _ENV_OVERRIDES.items():
        if env_name not in os.environ:
            continue
        target = getattr(cfg, section)
        current = getattr(target, field_name)
        try:
            setattr(target, field_name, _env_value(os.environ[env_name], current))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid {env_name}: {exc}") from exc


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"[{name}] must be a TOML table")
    return value




def _bm25_section(raw: dict[str, Any]) -> dict[str, Any]:
    """Load BM25 settings while ignoring legacy HTTP-only fields."""
    value = dict(_section(raw, "bm25"))
    value.pop("endpoint", None)
    value.pop("timeout_seconds", None)
    return value

def _http_url(name: str, value: Any, *, required: bool = True) -> str:
    if value in (None, ""):
        if required:
            raise ValueError(f"{name} must not be empty")
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string URL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{name} must be an http(s) URL")
    return value


def _as_int(name: str, value: Any, *, minimum: int = 1) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return parsed


def _as_float(name: str, value: Any, *, minimum: float | None = None, maximum: float | None = None, exclusive_min: bool = False) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if minimum is not None and (parsed <= minimum if exclusive_min else parsed < minimum):
        op = ">" if exclusive_min else ">="
        raise ValueError(f"{name} must be {op} {minimum}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return parsed


def _as_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be true or false")
    return value


def validate_config(cfg: Config) -> Config:
    cfg.llm.base_url = _http_url("llm.base_url", cfg.llm.base_url)
    if not isinstance(cfg.llm.model, str) or not cfg.llm.model.strip():
        raise ValueError("llm.model must not be empty")

    cfg.llm.timeout_seconds = _as_float("llm.timeout_seconds", cfg.llm.timeout_seconds, minimum=0, exclusive_min=True)
    cfg.llm.max_tokens = _as_int("llm.max_tokens", cfg.llm.max_tokens)
    cfg.llm.temperature = _as_float("llm.temperature", cfg.llm.temperature, minimum=0, maximum=2)
    cfg.bm25.top_k = _as_int("bm25.top_k", cfg.bm25.top_k)
    cfg.bm25.max_requests_per_candidate = _as_int("bm25.max_requests_per_candidate", cfg.bm25.max_requests_per_candidate)

    cfg.pipeline.max_candidates = _as_int("pipeline.max_candidates", cfg.pipeline.max_candidates)
    cfg.pipeline.max_hypotheses = _as_int("pipeline.max_hypotheses", cfg.pipeline.max_hypotheses)
    cfg.pipeline.max_comments = _as_int("pipeline.max_comments", cfg.pipeline.max_comments)
    cfg.pipeline.confidence_threshold = _as_float("pipeline.confidence_threshold", cfg.pipeline.confidence_threshold, minimum=0, maximum=1)
    cfg.pipeline.block_on_findings = _as_bool("pipeline.block_on_findings", cfg.pipeline.block_on_findings)
    cfg.pipeline.isolate_worktree = _as_bool("pipeline.isolate_worktree", cfg.pipeline.isolate_worktree)
    cfg.pipeline.keep_worktree = _as_bool("pipeline.keep_worktree", cfg.pipeline.keep_worktree)

    cfg.agents.stage1_max_steps = _as_int("agents.stage1_max_steps", cfg.agents.stage1_max_steps)
    cfg.agents.stage2_max_steps = _as_int("agents.stage2_max_steps", cfg.agents.stage2_max_steps)
    cfg.agents.stage3_max_steps = _as_int("agents.stage3_max_steps", cfg.agents.stage3_max_steps)
    cfg.agents.stage4_max_steps = _as_int("agents.stage4_max_steps", cfg.agents.stage4_max_steps)
    if cfg.agents.stage4_mode not in {"api", "agentic"}:
        raise ValueError("agents.stage4_mode must be 'api' or 'agentic'")

    cfg.repository.context_radius = _as_int("repository.context_radius", cfg.repository.context_radius)
    cfg.repository.max_read_lines = _as_int("repository.max_read_lines", cfg.repository.max_read_lines)
    cfg.repository.max_search_results = _as_int("repository.max_search_results", cfg.repository.max_search_results)

    cfg.ui.banner = _as_bool("ui.banner", cfg.ui.banner)
    cfg.ui.live_progress = _as_bool("ui.live_progress", cfg.ui.live_progress)
    cfg.ui.show_config = _as_bool("ui.show_config", cfg.ui.show_config)
    cfg.ui.show_stage_details = _as_bool("ui.show_stage_details", cfg.ui.show_stage_details)
    return cfg

def load_config(path: str | Path | None = None) -> Config:
    raw: dict[str, Any] = {}
    if path:
        p = Path(path).expanduser().resolve()
        if p.is_file():
            try:
                raw = tomllib.loads(p.read_text(encoding="utf-8"))
            except tomllib.TOMLDecodeError as exc:
                raise ValueError(f"Invalid TOML in {p}: {exc}") from exc
        else:
            raise FileNotFoundError(f"Config file not found: {p}")

    try:
        cfg = Config(
            llm=LLMConfig(**_section(raw, "llm")),
            bm25=BM25Config(**_bm25_section(raw)),
            pipeline=PipelineConfig(**_section(raw, "pipeline")),
            agents=AgentConfig(**_section(raw, "agents")),
            repository=RepositoryConfig(**_section(raw, "repository")),
            ui=UIConfig(**_section(raw, "ui")),
        )
    except TypeError as exc:
        raise ValueError(f"Unknown or invalid configuration field: {exc}") from exc

    # Backward-compatible OpenAI-style overrides. The ABH_* namespace below
    # can override every user-facing AgenticBugHunter setting.
    cfg.llm.base_url = os.getenv("OPENAI_BASE_URL", cfg.llm.base_url)
    cfg.llm.api_key = os.getenv("OPENAI_API_KEY", cfg.llm.api_key)
    cfg.llm.model = os.getenv("OPENAI_MODEL", cfg.llm.model)
    _apply_environment(cfg)
    return validate_config(cfg)
