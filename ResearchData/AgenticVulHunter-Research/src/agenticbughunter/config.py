from __future__ import annotations

import json
import math
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# LLM connection and generation settings
@dataclass
class LLMConfig:
    base_url: str = "http://localhost:11434/v1"
    api_key: str = "ollama"
    model: str = "qwen3-coder:30b"
    timeout_seconds: float = 800.0
    max_tokens: int = 6000
    temperature: float = 0.0
    provider: str = "openai"
    send_temperature: bool = True
    token_limit_field: str = "max_tokens"
    system_role: str = "system"
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0
    max_input_chars: int = 240000
    extra_body: dict[str, Any] = field(default_factory=dict)


# BM25 retrieval settings
@dataclass
class BM25Config:
    enabled: bool = True
    top_k: int = 10
    max_requests_per_candidate: int = 4


@dataclass
class PipelineConfig:
    # Research candidate generation is unbounded. This large fallback remains
    # for legacy prompt modes that still consume an integer configuration.
    max_candidates: int = 2_147_483_647
    max_hypotheses: int = 5
    confidence_threshold: float = 0.80
    skip_stage2: bool = False
    block_on_findings: bool = False
    isolate_worktree: bool = False
    keep_worktree: bool = False


@dataclass
class AgentConfig:
    stage1_max_steps: int = 50
    stage2_max_steps: int = 50
    stage3_max_steps: int = 50
    stage4_mode: str = "api"
    stage4_max_steps: int = 10


# Repository exploration limits
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


# Groups all configuration sections
@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    bm25: BM25Config = field(default_factory=BM25Config)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)
    repository: RepositoryConfig = field(default_factory=RepositoryConfig)
    ui: UIConfig = field(default_factory=UIConfig)


# Small set of settings that can be changed externally
_ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "ABH_LLM_BASE_URL": ("llm", "base_url"),
    "ABH_LLM_API_KEY": ("llm", "api_key"),
    "ABH_LLM_MODEL": ("llm", "model"),
    "ABH_PIPELINE_SKIP_STAGE2": ("pipeline", "skip_stage2"),
}


def environment_overrides() -> dict[str, tuple[str, str]]:
    return dict(_ENV_OVERRIDES)


def _env_value(raw: str, current: Any) -> Any:
    # Convert environment strings to the existing config type
    if isinstance(current, dict):
        return json.loads(raw)
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
    # Apply only the supported environment overrides
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
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            f"{name} must not contain credentials, query parameters, or fragments; use api_key"
        )
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


def _as_float(
    name: str,
    value: Any,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    exclusive_min: bool = False,
) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"{name} must be finite")
    if minimum is not None and (
        parsed <= minimum if exclusive_min else parsed < minimum
    ):
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
    # Validate LLM settings
    if cfg.llm.provider not in {"openai", "anthropic", "gemini"}:
        raise ValueError("llm.provider must be openai, anthropic, or gemini")
    if cfg.llm.system_role not in {"system", "developer", "user"}:
        raise ValueError("llm.system_role must be system, developer, or user")
    if cfg.llm.token_limit_field not in {"max_tokens", "max_completion_tokens", ""}:
        raise ValueError(
            "llm.token_limit_field must be max_tokens, max_completion_tokens, or empty"
        )
    cfg.llm.send_temperature = _as_bool(
        "llm.send_temperature", cfg.llm.send_temperature
    )
    cfg.llm.max_retries = _as_int("llm.max_retries", cfg.llm.max_retries, minimum=0)
    if cfg.llm.max_retries > 5:
        raise ValueError("llm.max_retries must be <= 5")
    cfg.llm.retry_backoff_seconds = _as_float(
        "llm.retry_backoff_seconds",
        cfg.llm.retry_backoff_seconds,
        minimum=0,
        maximum=30,
    )
    cfg.llm.max_input_chars = _as_int("llm.max_input_chars", cfg.llm.max_input_chars)
    if not isinstance(cfg.llm.extra_body, dict):
        raise ValueError("llm.extra_body must be a JSON object / TOML table")
    reserved = {
        "model",
        "messages",
        "contents",
        "system",
        "systemInstruction",
        "tools",
        "tool_choice",
        "toolConfig",
        "functions",
        "function_call",
        "parallel_tool_calls",
        "stream",
        "n",
        "candidateCount",
    }
    if reserved & cfg.llm.extra_body.keys():
        raise ValueError(
            "llm.extra_body cannot override model, messages, tools, streaming, or candidate count"
        )
    generation = cfg.llm.extra_body.get("generationConfig", {})
    if isinstance(generation, dict) and generation.get("candidateCount", 1) != 1:
        raise ValueError("llm.extra_body.generationConfig.candidateCount must be 1")
    try:
        json.dumps(cfg.llm.extra_body, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise ValueError("llm.extra_body must contain finite JSON values") from exc
    cfg.llm.base_url = _http_url("llm.base_url", cfg.llm.base_url)
    if not isinstance(cfg.llm.model, str) or not cfg.llm.model.strip():
        raise ValueError("llm.model must not be empty")

    cfg.llm.timeout_seconds = _as_float(
        "llm.timeout_seconds", cfg.llm.timeout_seconds, minimum=0, exclusive_min=True
    )
    cfg.llm.max_tokens = _as_int("llm.max_tokens", cfg.llm.max_tokens)
    cfg.llm.temperature = _as_float(
        "llm.temperature", cfg.llm.temperature, minimum=0, maximum=2
    )

    # Validate BM25 settings
    cfg.bm25.enabled = _as_bool("bm25.enabled", cfg.bm25.enabled)
    cfg.bm25.top_k = _as_int("bm25.top_k", cfg.bm25.top_k)
    cfg.bm25.max_requests_per_candidate = _as_int(
        "bm25.max_requests_per_candidate", cfg.bm25.max_requests_per_candidate
    )

    # Validate pipeline settings
    cfg.pipeline.max_candidates = _as_int(
        "pipeline.max_candidates", cfg.pipeline.max_candidates
    )
    cfg.pipeline.max_hypotheses = _as_int(
        "pipeline.max_hypotheses", cfg.pipeline.max_hypotheses
    )
    cfg.pipeline.confidence_threshold = _as_float(
        "pipeline.confidence_threshold",
        cfg.pipeline.confidence_threshold,
        minimum=0,
        maximum=1,
    )
    cfg.pipeline.skip_stage2 = _as_bool(
        "pipeline.skip_stage2", cfg.pipeline.skip_stage2
    )
    cfg.pipeline.block_on_findings = _as_bool(
        "pipeline.block_on_findings", cfg.pipeline.block_on_findings
    )
    cfg.pipeline.isolate_worktree = _as_bool(
        "pipeline.isolate_worktree", cfg.pipeline.isolate_worktree
    )
    cfg.pipeline.keep_worktree = _as_bool(
        "pipeline.keep_worktree", cfg.pipeline.keep_worktree
    )

    # Validate agent limits
    cfg.agents.stage1_max_steps = _as_int(
        "agents.stage1_max_steps", cfg.agents.stage1_max_steps
    )
    cfg.agents.stage2_max_steps = _as_int(
        "agents.stage2_max_steps", cfg.agents.stage2_max_steps
    )
    cfg.agents.stage3_max_steps = _as_int(
        "agents.stage3_max_steps", cfg.agents.stage3_max_steps
    )
    cfg.agents.stage4_max_steps = _as_int(
        "agents.stage4_max_steps", cfg.agents.stage4_max_steps
    )
    if cfg.agents.stage4_mode not in {"api", "agentic"}:
        raise ValueError("agents.stage4_mode must be 'api' or 'agentic'")

    # Validate repository limits
    cfg.repository.context_radius = _as_int(
        "repository.context_radius", cfg.repository.context_radius
    )
    cfg.repository.max_read_lines = _as_int(
        "repository.max_read_lines", cfg.repository.max_read_lines
    )
    cfg.repository.max_search_results = _as_int(
        "repository.max_search_results", cfg.repository.max_search_results
    )

    cfg.ui.banner = _as_bool("ui.banner", cfg.ui.banner)
    cfg.ui.live_progress = _as_bool("ui.live_progress", cfg.ui.live_progress)
    cfg.ui.show_config = _as_bool("ui.show_config", cfg.ui.show_config)
    cfg.ui.show_stage_details = _as_bool(
        "ui.show_stage_details", cfg.ui.show_stage_details
    )
    return cfg


def load_config(
    path: str | Path | None = None, *, use_environment: bool = True
) -> Config:
    """Load the configuration used by AgenticVulHunter."""

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

    # Use only the loaded configuration when environment overrides are disabled
    if not use_environment:
        return validate_config(cfg)

    # Connection details can still come from the environment
    cfg.llm.base_url = os.getenv("OPENAI_BASE_URL", cfg.llm.base_url)
    cfg.llm.api_key = os.getenv("OPENAI_API_KEY", cfg.llm.api_key)
    cfg.llm.model = os.getenv("OPENAI_MODEL", cfg.llm.model)

    _apply_environment(cfg)
    return validate_config(cfg)