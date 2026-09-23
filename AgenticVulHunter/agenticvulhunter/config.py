"""Small runtime configuration for AgenticVulHunter.

The public setup contains the LLM endpoint, API key, and model. They can come
from AVH_ENDPOINT / AVH_API_KEY / AVH_MODEL or from avh_setup.toml. All other
research settings stay inside the tool so normal runs use the same pipeline
configuration.
"""

from __future__ import annotations

import math
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_MODEL = "qwen3-coder:30b"


@dataclass
class LLMConfig:
    # Public LLM setup.
    base_url: str = "http://localhost:11434/v1"
    api_key: str = ""
    model: str = DEFAULT_MODEL

    # Internal research defaults.
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


@dataclass
class BM25Config:
    top_k: int = 10
    max_requests_per_candidate: int = 4


@dataclass
class PipelineConfig:
    max_hypotheses: int = 5


@dataclass
class AgentConfig:
    stage1_max_steps: int = 50
    stage2_max_steps: int = 50
    stage3_max_steps: int = 50


@dataclass
class RepositoryConfig:
    context_radius: int = 200
    max_read_lines: int = 300
    max_search_results: int = 30


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    bm25: BM25Config = field(default_factory=BM25Config)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)
    repository: RepositoryConfig = field(default_factory=RepositoryConfig)


def _http_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("llm.endpoint must not be empty")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("llm.endpoint must be an http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("llm.endpoint must be a plain endpoint URL")
    return value.rstrip("/")


def _positive_int(name: str, value: Any, minimum: int = 1) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if number < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return number


def _number(name: str, value: Any, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return number


def validate_config(cfg: Config) -> Config:
    cfg.llm.base_url = _http_url(cfg.llm.base_url)
    if not isinstance(cfg.llm.api_key, str):
        raise ValueError("llm.api_key must be a string")
    if not isinstance(cfg.llm.model, str) or not cfg.llm.model.strip():
        raise ValueError("llm.model must not be empty")

    cfg.llm.timeout_seconds = _number(
        "llm.timeout_seconds", cfg.llm.timeout_seconds, 1.0, 3600.0
    )
    cfg.llm.max_tokens = _positive_int("llm.max_tokens", cfg.llm.max_tokens)
    cfg.llm.temperature = _number("llm.temperature", cfg.llm.temperature, 0.0, 2.0)
    cfg.llm.max_retries = _positive_int("llm.max_retries", cfg.llm.max_retries, 0)
    cfg.llm.max_input_chars = _positive_int(
        "llm.max_input_chars", cfg.llm.max_input_chars
    )
    cfg.bm25.top_k = _positive_int("bm25.top_k", cfg.bm25.top_k)
    cfg.bm25.max_requests_per_candidate = _positive_int(
        "bm25.max_requests_per_candidate", cfg.bm25.max_requests_per_candidate
    )
    cfg.pipeline.max_hypotheses = _positive_int(
        "pipeline.max_hypotheses", cfg.pipeline.max_hypotheses
    )
    cfg.agents.stage1_max_steps = _positive_int(
        "agents.stage1_max_steps", cfg.agents.stage1_max_steps
    )
    cfg.agents.stage2_max_steps = _positive_int(
        "agents.stage2_max_steps", cfg.agents.stage2_max_steps
    )
    cfg.agents.stage3_max_steps = _positive_int(
        "agents.stage3_max_steps", cfg.agents.stage3_max_steps
    )
    cfg.repository.context_radius = _positive_int(
        "repository.context_radius", cfg.repository.context_radius
    )
    cfg.repository.max_read_lines = _positive_int(
        "repository.max_read_lines", cfg.repository.max_read_lines
    )
    cfg.repository.max_search_results = _positive_int(
        "repository.max_search_results", cfg.repository.max_search_results
    )
    return cfg


def load_config(path: str | Path | None = None) -> Config:
    """Load connection details from TOML, then allow AVH exports to override them."""
    cfg = Config()

    if path is not None:
        config_path = Path(path).expanduser().resolve()
        if not config_path.is_file():
            raise FileNotFoundError(f"Setup file not found: {config_path}")
        try:
            raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Invalid TOML in {config_path}: {exc}") from exc

        unknown_sections = set(raw) - {"llm"}
        if unknown_sections:
            names = ", ".join(sorted(unknown_sections))
            raise ValueError(f"Only the [llm] section is supported; remove: {names}")

        llm = raw.get("llm", {})
        if not isinstance(llm, dict):
            raise ValueError("[llm] must be a TOML table")

        unknown_fields = set(llm) - {"endpoint", "api_key", "model"}
        if unknown_fields:
            names = ", ".join(sorted(unknown_fields))
            raise ValueError(f"[llm] only supports endpoint, api_key, and model; remove: {names}")

        if "endpoint" in llm:
            cfg.llm.base_url = llm["endpoint"]
        if "api_key" in llm:
            cfg.llm.api_key = llm["api_key"]
        if "model" in llm:
            cfg.llm.model = llm["model"]

    # Exports take priority so a user can override a local setup file temporarily.
    if os.getenv("AVH_ENDPOINT"):
        cfg.llm.base_url = os.environ["AVH_ENDPOINT"]
    if os.getenv("AVH_API_KEY") is not None:
        cfg.llm.api_key = os.environ["AVH_API_KEY"]
    if os.getenv("AVH_MODEL"):
        cfg.llm.model = os.environ["AVH_MODEL"]

    return validate_config(cfg)
