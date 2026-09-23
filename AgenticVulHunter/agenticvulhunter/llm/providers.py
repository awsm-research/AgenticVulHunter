"""Pure request/response adapters; 

Protocol references and extension instructions are in docs/models.md. Keep
provider payload conventions here, outside the four research stages.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..config import LLMConfig


def _merge_turns(messages: list[dict[str, str]]) -> tuple[str, list[dict[str, str]]]:
    """Separate instructions and combine adjacent turns for strict chat APIs."""
    system = []
    turns: list[dict[str, str]] = []
    for message in messages:
        role, content = message["role"], message["content"]
        if role in {"system", "developer"}:
            system.append(content)
        elif role in {"user", "assistant"}:
            if turns and turns[-1]["role"] == role:
                turns[-1]["content"] += "\n\n" + content
            else:
                turns.append(dict(message))
        else:
            raise ValueError(f"Unsupported message role: {role}")
    return "\n\n".join(system), turns


def build_request(
    config: LLMConfig,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
) -> tuple[str, dict, dict]:
    """Return (URL, headers, JSON body) without mutating messages/config."""
    base = config.base_url.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if config.provider == "openai":
        endpoint = (
            base if base.endswith("/chat/completions") else base + "/chat/completions"
        )
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        if config.system_role == "user":
            system, turns = _merge_turns(messages)
            wire_messages = (
                [{"role": "user", "content": system}] if system else []
            ) + turns
            _, wire_messages = _merge_turns(wire_messages)
        else:
            wire_messages = [
                dict(m, role=config.system_role) if m["role"] == "system" else dict(m)
                for m in messages
            ]
        payload: dict[str, Any] = {"model": config.model, "messages": wire_messages}
        if config.token_limit_field:
            payload[config.token_limit_field] = max_tokens
        if config.send_temperature:
            payload["temperature"] = temperature
    elif config.provider == "anthropic":
        endpoint = base if base.endswith("/messages") else base + "/messages"
        headers.update({"x-api-key": config.api_key, "anthropic-version": "2023-06-01"})
        system, turns = _merge_turns(messages)
        payload = {"model": config.model, "messages": turns, "max_tokens": max_tokens}
        if system:
            payload["system"] = system
        if config.send_temperature:
            payload["temperature"] = temperature
    elif config.provider == "gemini":
        model = config.model.removeprefix("models/")
        endpoint = base + "/models/" + quote(model, safe="") + ":generateContent"
        headers["x-goog-api-key"] = config.api_key
        system, turns = _merge_turns(messages)
        generation = {"maxOutputTokens": max_tokens}
        if config.send_temperature:
            generation["temperature"] = temperature
        payload = {
            "contents": [
                {
                    "role": "model" if m["role"] == "assistant" else "user",
                    "parts": [{"text": m["content"]}],
                }
                for m in turns
            ],
            "generationConfig": generation,
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
    else:
        raise ValueError(f"Unknown LLM provider: {config.provider}")

    # Provider knobs such as reasoning budgets are opt-in. Merge one level so
    # Gemini generationConfig extensions do not discard the output limit.
    for key, value in config.extra_body.items():
        if (
            key in payload
            and isinstance(payload[key], dict)
            and isinstance(value, dict)
        ):
            payload[key] = {**payload[key], **value}
        else:
            payload[key] = value
    return endpoint, headers, payload


def _text_blocks(blocks: Any, *, gemini: bool = False) -> str:
    if not isinstance(blocks, list):
        raise ValueError("Expected a list of response content blocks")
    return "".join(
        b["text"]
        for b in blocks
        if isinstance(b, dict)
        and isinstance(b.get("text"), str)
        and (
            not b.get("thought") if gemini else b.get("type") in {"text", "output_text"}
        )
    )


def parse_response(provider: str, raw: dict[str, Any]) -> tuple[str, dict]:
    """Normalize final text and usage; fail explicitly on truncation/refusal."""
    try:
        if provider == "openai":
            choice = raw["choices"][0]
            reason = choice.get("finish_reason")
            message = choice["message"]
            if message.get("tool_calls") or message.get("function_call"):
                raise ValueError(
                    "Native tool calls are unsupported; return JSON actions in message content"
                )
            if message.get("refusal") or reason == "content_filter":
                raise ValueError("Model refused or filtered this request")
            content = message.get("content")
            text = content if isinstance(content, str) else _text_blocks(content)
            usage = raw.get("usage", {})
        elif provider == "anthropic":
            reason = raw.get("stop_reason")
            if any(
                b.get("type") == "tool_use"
                for b in raw.get("content", [])
                if isinstance(b, dict)
            ):
                raise ValueError(
                    "Native tool calls are unsupported; return text JSON actions"
                )
            if reason == "refusal":
                raise ValueError("Model refused this request")
            text, usage = _text_blocks(raw["content"]), raw.get("usage", {})
        elif provider == "gemini":
            candidate = raw["candidates"][0]
            reason = candidate.get("finishReason")
            if reason not in {None, "STOP", "MAX_TOKENS"}:
                raise ValueError(f"Model did not complete normally: {reason}")
            parts = candidate["content"]["parts"]
            if any("functionCall" in b for b in parts):
                raise ValueError(
                    "Native tool calls are unsupported; return text JSON actions"
                )
            text, usage = _text_blocks(parts, gemini=True), raw.get("usageMetadata", {})
        else:
            raise ValueError(f"Unknown provider: {provider}")
        if reason in {"length", "max_tokens", "MAX_TOKENS"}:
            raise ValueError(
                "Model output was truncated; increase the internal output token limit or reduce supplied context"
            )
        if not text.strip():
            raise ValueError(
                "Model returned no final text; check reasoning budget, refusal, and output limits"
            )
        return text, usage if isinstance(usage, dict) else {}
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(
            f"Malformed {provider} response: missing expected text fields"
        ) from exc
