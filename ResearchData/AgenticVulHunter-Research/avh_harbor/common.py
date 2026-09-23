"""Small shared helpers used by the Harbor adapter."""

import hashlib
import os
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parent.parent
AGENT_SPEC = "run_avh_research_harbor:AgenticVulHunterResearchAgent"
LOG_ROOT = "/logs/agent/agenticvulhunter"
WRAPPER_VERSION = "1.1.0"

PROVIDER_ENV_KEYS = {
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
}


def container_runtime_env(source: dict[str, str] | None = None) -> dict[str, str]:
    """Forward only AVH configuration and provider credentials."""
    values = os.environ if source is None else source
    return {
        key: value
        for key, value in values.items()
        if key.startswith("ABH_") or key in PROVIDER_ENV_KEYS
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def result_code(result: Any) -> int | None:
    return getattr(result, "return_code", getattr(result, "returncode", 0))


def stdout(result: Any) -> str:
    return str(getattr(result, "stdout", "") or "")


def stderr(result: Any) -> str:
    return str(getattr(result, "stderr", "") or "")
