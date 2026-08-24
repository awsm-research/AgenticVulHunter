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
    endpoint: str = "http://localhost:5056/predict"
    timeout_seconds: float = 120.0
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
    stage1_max_steps: int = 4
    stage2_max_steps: int = 10
    stage3_max_steps: int = 8
    stage4_mode: str = "api"
    stage4_max_steps: int = 5


@dataclass
class RepositoryConfig:
    context_radius: int = 20
    max_read_lines: int = 220
    max_search_results: int = 30


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    bm25: BM25Config = field(default_factory=BM25Config)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)
    repository: RepositoryConfig = field(default_factory=RepositoryConfig)


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"[{name}] must be a TOML table")
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
    cfg.bm25.endpoint = _http_url("bm25.endpoint", cfg.bm25.endpoint)
    if not isinstance(cfg.llm.model, str) or not cfg.llm.model.strip():
        raise ValueError("llm.model must not be empty")

    cfg.llm.timeout_seconds = _as_float("llm.timeout_seconds", cfg.llm.timeout_seconds, minimum=0, exclusive_min=True)
    cfg.llm.max_tokens = _as_int("llm.max_tokens", cfg.llm.max_tokens)
    cfg.llm.temperature = _as_float("llm.temperature", cfg.llm.temperature, minimum=0, maximum=2)
    cfg.bm25.timeout_seconds = _as_float("bm25.timeout_seconds", cfg.bm25.timeout_seconds, minimum=0, exclusive_min=True)
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
            bm25=BM25Config(**_section(raw, "bm25")),
            pipeline=PipelineConfig(**_section(raw, "pipeline")),
            agents=AgentConfig(**_section(raw, "agents")),
            repository=RepositoryConfig(**_section(raw, "repository")),
        )
    except TypeError as exc:
        raise ValueError(f"Unknown or invalid configuration field: {exc}") from exc

    cfg.llm.base_url = os.getenv("OPENAI_BASE_URL", cfg.llm.base_url)
    cfg.llm.api_key = os.getenv("OPENAI_API_KEY", cfg.llm.api_key)
    cfg.llm.model = os.getenv("OPENAI_MODEL", cfg.llm.model)
    cfg.bm25.endpoint = os.getenv("SAST_RETRIEVER_URL", cfg.bm25.endpoint)
    return validate_config(cfg)
