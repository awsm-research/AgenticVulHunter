"""Provider-independent boundary used by every research stage.

A backend accepts ordinary chat messages and returns text. It does not execute
repository operations or choose the review algorithm.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class LLMResponse:
    content: str
    usage: dict[str, Any]
    raw: dict[str, Any]
    duration_ms: float


class ChatClient(Protocol):
    """Implement this interface to plug in an SDK, local model, or test double."""

    def chat(
        self, messages: list[dict[str, str]], *,
        temperature: float | None = None, max_tokens: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> LLMResponse: ...
