from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .client import OpenAICompatibleClient
from ..runlog import RunLogger


_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.I | re.S)


def extract_json_value(text: str) -> Any:
    """Extract the first valid JSON object/array from model output."""
    candidates = [text.strip()]
    candidates += [m.group(1).strip() for m in _JSON_FENCE.finditer(text)]
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text[i:])
            return value
        except json.JSONDecodeError:
            continue
    raise ValueError("No valid JSON object or array found in model output")


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, str]
    handler: Callable[[dict[str, Any]], Any]

    def schema_text(self) -> str:
        return json.dumps({
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }, ensure_ascii=False)


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None):
        self._tools = {tool.name: tool for tool in (tools or [])}

    def names(self) -> list[str]:
        return list(self._tools)

    def describe(self) -> str:
        return "\n".join(f"- {tool.schema_text()}" for tool in self._tools.values()) or "(no tools)"

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name not in self._tools:
            raise KeyError(f"Unknown tool {name!r}; available: {', '.join(self.names())}")
        return self._tools[name].handler(arguments)


class AgentRunner:

    PROTOCOL = """
You have access to read-only tools. On every turn return exactly ONE JSON object.
To use a tool:
{"type":"tool","tool":"TOOL_NAME","arguments":{},"reason":"short reason"}
To finish:
{"type":"final","answer": <the requested final JSON value>}
Never place prose outside that JSON object. Never invent a tool result.
""".strip()

    def __init__(
        self,
        client: OpenAICompatibleClient,
        tools: ToolRegistry,
        logger: RunLogger,
        *,
        stage: str,
        max_steps: int,
        artifact_dir: Path,
    ):
        self.client = client
        self.tools = tools
        self.logger = logger
        self.stage = stage
        self.max_steps = max_steps
        self.artifact_dir = artifact_dir
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    def run(self, system_prompt: str, user_prompt: str) -> Any:
        messages: list[dict[str, str]] = [
            {
                "role": "system",
                "content": system_prompt + "\n\n" + self.PROTOCOL + "\n\nAVAILABLE TOOLS:\n" + self.tools.describe(),
            },
            {"role": "user", "content": user_prompt},
        ]
        conversation_path = self.artifact_dir / "conversation.jsonl"

        for step in range(1, self.max_steps + 1):
            response = self.client.chat(messages, metadata={"stage": self.stage, "agent_step": step})
            self._append_conversation(conversation_path, {
                "step": step,
                "role": "assistant",
                "content": response.content,
                "usage": response.usage,
            })
            try:
                action = extract_json_value(response.content)
            except ValueError as exc:
                observation = {
                    "error": "invalid_json_action",
                    "detail": str(exc),
                    "instruction": "Return exactly one valid JSON action object.",
                }
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": "OBSERVATION:\n" + json.dumps(observation)})
                continue

            if not isinstance(action, dict):
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": 'OBSERVATION: action must be a JSON object with type="tool" or type="final".'})
                continue

            kind = str(action.get("type") or "").lower()
            if kind == "final":
                self.logger.event("agent_final", {"stage": self.stage, "step": step, "answer": action.get("answer")})
                return action.get("answer")

            if kind != "tool":
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": 'OBSERVATION: unknown action type. Use "tool" or "final".'})
                continue

            tool_name = str(action.get("tool") or "")
            arguments = action.get("arguments") or {}
            if not isinstance(arguments, dict):
                arguments = {}
            try:
                result = self.tools.call(tool_name, arguments)
                observation = {"tool": tool_name, "ok": True, "result": result}
            except Exception as exc:
                observation = {"tool": tool_name, "ok": False, "error_type": type(exc).__name__, "error": str(exc)}

            self.logger.event("agent_tool", {
                "stage": self.stage,
                "step": step,
                "tool": tool_name,
                "arguments": arguments,
                "observation": observation,
            })
            self._append_conversation(conversation_path, {
                "step": step,
                "role": "tool",
                "content": observation,
            })
            messages.append({"role": "assistant", "content": json.dumps(action, ensure_ascii=False)})
            messages.append({"role": "user", "content": "OBSERVATION:\n" + json.dumps(observation, ensure_ascii=False)})

        raise RuntimeError(f"{self.stage} agent exceeded max_steps={self.max_steps} without returning a final answer")

    @staticmethod
    def _append_conversation(path: Path, value: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(value, ensure_ascii=False) + "\n")
