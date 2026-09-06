"""Dependency-free HTTP transport with bounded retries and explicit failures."""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any

from ..config import LLMConfig
from ..runlog import RunLogger
from .providers import build_request, parse_response
from .types import LLMResponse

_RETRYABLE = {408, 429, 500, 502, 503, 504, 529}
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward API credentials to a redirected endpoint."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTPChatClient:
    """Text-only chat transport; provider differences live in providers.py."""

    def __init__(self, config: LLMConfig, logger: RunLogger | None = None):
        self.config = config
        self.logger = logger
        self._opener = urllib.request.build_opener(_NoRedirect())

    @property
    def endpoint(self) -> str:
        return build_request(self.config, [], self.config.temperature, self.config.max_tokens)[0]

    def _safe_detail(self, detail: str) -> str:
        return detail.replace(self.config.api_key, '***REDACTED***')[:1000] if self.config.api_key else detail[:1000]

    def _post(self, request: urllib.request.Request) -> dict[str, Any]:
        """Retry transient HTTP/network errors, never schema/auth/model errors."""
        for attempt in range(self.config.max_retries + 1):
            try:
                with self._opener.open(request, timeout=self.config.timeout_seconds) as response:
                    data = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(data) > _MAX_RESPONSE_BYTES:
                    raise RuntimeError('LLM response exceeded 16 MiB')
                raw = json.loads(data.decode('utf-8'))
                if not isinstance(raw, dict):
                    raise RuntimeError('LLM response must be a JSON object')
                return raw
            except urllib.error.HTTPError as exc:
                detail = self._safe_detail(exc.read(4096).decode('utf-8', errors='replace'))
                if exc.code not in _RETRYABLE or attempt == self.config.max_retries:
                    raise RuntimeError(f'LLM HTTP {exc.code}: {detail}') from exc
                delay = min(30.0, self.config.retry_backoff_seconds * 2 ** attempt)
                try:
                    delay = min(30.0, max(delay, float(exc.headers.get('Retry-After', 0))))
                except (ValueError, TypeError, AttributeError):
                    pass
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                if attempt == self.config.max_retries:
                    raise RuntimeError(f'Unable to reach LLM endpoint: {self._safe_detail(str(exc))}') from exc
                delay = min(30.0, self.config.retry_backoff_seconds * 2 ** attempt)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RuntimeError('LLM endpoint returned invalid JSON; check the provider and base URL') from exc
            if self.logger:
                self.logger.event('llm_retry', {'attempt': attempt + 1, 'delay_seconds': delay})
            time.sleep(delay)
        raise AssertionError('unreachable')

    def chat(self, messages: list[dict[str, str]], *, temperature: float | None = None,
             max_tokens: int | None = None, metadata: dict[str, Any] | None = None) -> LLMResponse:
        if sum(len(m['content']) for m in messages) > self.config.max_input_chars:
            raise RuntimeError('Input exceeds ABH_LLM_MAX_INPUT_CHARS; reduce the diff/context or raise the explicit budget')
        endpoint, headers, payload = build_request(
            self.config, messages,
            self.config.temperature if temperature is None else temperature,
            self.config.max_tokens if max_tokens is None else max_tokens,
        )
        request = urllib.request.Request(endpoint, data=json.dumps(payload, allow_nan=False).encode('utf-8'),
                                         headers=headers, method='POST')
        started = time.monotonic()
        raw = self._post(request)
        try:
            content, usage = parse_response(self.config.provider, raw)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        duration_ms = (time.monotonic() - started) * 1000
        if self.logger:
            self.logger.event('llm_call', {
                'provider': self.config.provider, 'model': self.config.model,
                'duration_ms': duration_ms, 'usage': usage, 'metadata': metadata or {},
                'request_messages': messages, 'response_content': content,
            })
        return LLMResponse(content, usage, raw, duration_ms)


# Preserve the old import path for integrations. New code uses create_client.
class OpenAICompatibleClient(HTTPChatClient):
    pass


def create_client(config: LLMConfig, logger: RunLogger | None = None) -> HTTPChatClient:
    """Construct a text backend from the validated provider configuration."""
    return HTTPChatClient(config, logger)
