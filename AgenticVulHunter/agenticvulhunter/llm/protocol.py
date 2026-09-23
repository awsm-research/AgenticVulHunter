"""Text JSON protocol shared by all providers; no vendor tool-call schema."""

from __future__ import annotations

import json
import re
from typing import Any

PROTOCOL = """
You have access to read-only tools.

TO USE A TOOL, return exactly one JSON object:

{
  "type": "tool",
  "tool": "TOOL_NAME",
  "arguments": {},
  "reason": "short reason"
}

When you have enough evidence, STOP using tools and return the final JSON
value requested by the stage prompt.

For example, if the stage asks for a JSON array, return the JSON array
directly.

If the stage asks for a JSON object, return that JSON object directly.

A wrapped final answer is also accepted:

{
  "type": "final",
  "answer": <requested final JSON value>
}

Rules:
- Never place prose outside the JSON.
- Never invent a tool result.
- Return only ONE tool call per response.
- Wait for the tool observation before choosing another tool.
- Do not batch multiple tool calls in one response.
- Do not repeat a final answer.
- Do not continue calling tools once sufficient evidence has been gathered.
- Repository context may inform your reasoning, but obey all localization
  and output constraints given by the stage prompt.
- Always produce syntactically valid JSON.
- Escape embedded double quotes inside JSON strings.
""".strip()


def extract_json_value(text: str) -> Any:
    """Accept one JSON value, optionally fenced or preceded by prose.

    Never salvage an inner item from a malformed array and never discard a
    second JSON value. Invalid output is retried by the runner, not executed.
    A complete leading <think> block is ignored, not treated as an action.
    """
    value = re.sub(
        r"^\s*<think>.*?</think>\s*", "", text, count=1, flags=re.DOTALL
    ).strip()
    if value.startswith("```"):
        match = re.fullmatch(
            r"```(?:json)?\s*([\s\S]*?)\s*```", value, flags=re.IGNORECASE
        )
        if not match:
            raise ValueError("Return exactly one complete JSON code fence")
        value = match.group(1).strip()
    elif not value.startswith(("{", "[")):
        positions = [i for i in (value.find("{"), value.find("[")) if i >= 0]
        if not positions:
            raise ValueError("No JSON object or array found")
        value = value[min(positions) :]
    try:
        result = json.loads(value)
    except json.JSONDecodeError as exc:
        # Some OpenAI-compatible text endpoints append a lone Markdown closing
        # fence even though they never opened one. Accept only that exact
        # transport suffix, and only when removing it reveals one already
        # complete JSON value. Never complete or reconstruct malformed JSON.
        without_trailing_fence = re.sub(r"\s*```\s*\Z", "", value, count=1)
        if without_trailing_fence != value:
            try:
                result = json.loads(without_trailing_fence)
            except json.JSONDecodeError:
                pass
            else:
                if isinstance(result, (dict, list)):
                    return result
        raise ValueError(
            "Return one complete JSON object or array; malformed or multiple "
            f"values are not accepted. JSON error at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(result, (dict, list)):
        raise ValueError(  # noqa: TRY004 - protocol validation is retried as ValueError
            "Final output must be a JSON object or array"
        )
    return result
