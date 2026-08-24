from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from ..config import LLMConfig
from ..runlog import RunLogger


@dataclass
class LLMResponse:
    content: str
    usage: dict[str, Any]
    raw: dict[str, Any]
    duration_ms: float


class OpenAICompatibleClient:
    """Tiny dependency-free OpenAI-compatible chat client.

    Works with endpoints that implement POST /chat/completions, including
    Ollama's OpenAI compatibility layer, OpenRouter, vLLM and LM Studio.
    """

    def __init__(self, config: LLMConfig, logger: RunLogger | None = None):
        self.config = config
        self.logger = logger

    @property
    def endpoint(self) -> str:
        base = self.config.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> LLMResponse:
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature if temperature is None else temperature,
            "max_tokens": self.config.max_tokens if max_tokens is None else max_tokens,
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw_text = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if self.logger:
                self.logger.event("llm_http_error", {
                    "status": exc.code,
                    "endpoint": self.endpoint,
                    "detail": detail[:4000],
                    "metadata": metadata or {},
                })
            raise RuntimeError(f"LLM endpoint returned HTTP {exc.code}: {detail[:1000]}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise RuntimeError(f"Unable to reach LLM endpoint {self.endpoint}: {exc}") from exc

        duration_ms = (time.monotonic() - started) * 1000.0
        try:
            raw = json.loads(raw_text)
            content = raw["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"Malformed OpenAI-compatible response: {raw_text[:1500]}") from exc

        usage = raw.get("usage") if isinstance(raw, dict) else {}
        if not isinstance(usage, dict):
            usage = {}
        if self.logger:
            self.logger.event("llm_call", {
                "endpoint": self.endpoint,
                "model": self.config.model,
                "duration_ms": duration_ms,
                "usage": usage,
                "metadata": metadata or {},
                "request_messages": messages,
                "response_content": content,
            })
        return LLMResponse(str(content or ""), usage, raw, duration_ms)
