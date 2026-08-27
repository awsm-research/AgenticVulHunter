from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .client import OpenAICompatibleClient
from ..runlog import RunLogger


_JSON_FENCE = re.compile(
    r"```(?:json)?\s*(.*?)```",
    re.I | re.S,
)


def extract_json_value(text: str) -> Any:
    """
    Extract one valid JSON action or final value.

    Behaviour:
    - Valid complete JSON -> return it.
    - Malformed top-level final array -> reject it.
    - Multiple consecutive tool objects -> execute only the first tool.
    - Prose followed by JSON -> recover the JSON.
    """

    stripped = text.strip()

    # ---------------------------------------------------------
    # 1. Try the complete response first
    # ---------------------------------------------------------

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # ---------------------------------------------------------
    # 2. Try fenced JSON
    # ---------------------------------------------------------

    for match in _JSON_FENCE.finditer(text):
        candidate = match.group(1).strip()

        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    decoder = json.JSONDecoder()

    # ---------------------------------------------------------
    # 3. Malformed top-level ARRAY
    # ---------------------------------------------------------
    #
    # Important for Stage 1.
    #
    # If the model attempted:
    #
    # [
    #   {broken candidate},
    #   {valid candidate}
    # ]
    #
    # do NOT salvage one inner candidate.
    # Reject the complete response and make the agent retry.
    # ---------------------------------------------------------

    if stripped.startswith("["):
        raise ValueError(
            "Model returned malformed top-level JSON array"
        )

    # ---------------------------------------------------------
    # 4. Top-level OBJECT
    # ---------------------------------------------------------
    #
    # Qwen may sometimes return:
    #
    # {"type":"tool", ...}
    # {"type":"tool", ...}
    # {"type":"tool", ...}
    #
    # AgentRunner operates sequentially, so use only the first
    # tool call. Its observation is then returned to the model.
    # ---------------------------------------------------------

    if stripped.startswith("{"):
        try:
            value, end = decoder.raw_decode(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "Model returned malformed top-level JSON object"
            ) from exc

        trailing = stripped[end:].strip()

        # One clean JSON object.
        if not trailing:
            return value

        # Multiple JSON values.
        # Accept only the first if it is a tool call.
        if (
            isinstance(value, dict)
            and str(value.get("type") or "").lower() == "tool"
        ):
            return value

        # Never silently discard additional final objects.
        raise ValueError(
            "Model returned multiple top-level JSON values"
        )

    # ---------------------------------------------------------
    # 5. Prose followed by JSON
    # ---------------------------------------------------------

    for i, ch in enumerate(text):
        if ch not in "[{":
            continue

        try:
            value, _ = decoder.raw_decode(text[i:])
            return value
        except json.JSONDecodeError:
            continue

    raise ValueError(
        "No valid JSON object or array found in model output"
    )


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, str]
    handler: Callable[[dict[str, Any]], Any]

    def schema_text(self) -> str:
        return json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
            ensure_ascii=False,
        )


class ToolRegistry:
    def __init__(
        self,
        tools: list[Tool] | None = None,
    ):
        self._tools = {
            tool.name: tool
            for tool in (tools or [])
        }

    def names(self) -> list[str]:
        return list(self._tools)

    def describe(self) -> str:
        if not self._tools:
            return "(no tools)"

        return "\n".join(
            f"- {tool.schema_text()}"
            for tool in self._tools.values()
        )

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> Any:
        if name not in self._tools:
            raise KeyError(
                f"Unknown tool {name!r}; "
                f"available: {', '.join(self.names())}"
            )

        return self._tools[name].handler(arguments)


class AgentRunner:

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

        self.artifact_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    def run(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> Any:

        messages: list[dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    system_prompt
                    + "\n\n"
                    + self.PROTOCOL
                    + "\n\nAVAILABLE TOOLS:\n"
                    + self.tools.describe()
                ),
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ]

        conversation_path = (
            self.artifact_dir
            / "conversation.jsonl"
        )

        previous_response: str | None = None
        repeated_response_count = 0

        for step in range(
            1,
            self.max_steps + 1,
        ):

            # -------------------------------------------------
            # Final-step protection
            # -------------------------------------------------

            if step == self.max_steps:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "FINAL STEP: You have reached the final "
                            "allowed agent step. Do not call another "
                            "tool. Return the requested final JSON "
                            "answer now."
                        ),
                    }
                )

            response = self.client.chat(
                messages,
                metadata={
                    "stage": self.stage,
                    "agent_step": step,
                },
            )

            self._append_conversation(
                conversation_path,
                {
                    "step": step,
                    "role": "assistant",
                    "content": response.content,
                    "usage": response.usage,
                },
            )

            # -------------------------------------------------
            # Detect exact repeated responses
            # -------------------------------------------------

            normalized_response = response.content.strip()

            if normalized_response == previous_response:
                repeated_response_count += 1
            else:
                repeated_response_count = 0

            previous_response = normalized_response

            if repeated_response_count >= 2:
                self.logger.event(
                    "agent_repetition_detected",
                    {
                        "stage": self.stage,
                        "step": step,
                    },
                )

                raise RuntimeError(
                    f"{self.stage} agent repeated "
                    "the same response multiple times "
                    "without terminating"
                )

            # -------------------------------------------------
            # Parse JSON
            # -------------------------------------------------

            try:
                action = extract_json_value(
                    response.content
                )

            except ValueError as exc:
                observation = {
                    "error": "invalid_json_action",
                    "detail": str(exc),
                    "instruction": (
                        "Your previous response contained malformed JSON. "
                        "Return the COMPLETE requested JSON value again. "
                        "If using a tool, return exactly ONE tool call. "
                        "Do not return multiple tool calls together. "
                        "Do not return only one item from a final array. "
                        "Ensure embedded quotes inside JSON strings are escaped."
                    ),
                }

                messages.append(
                    {
                        "role": "assistant",
                        "content": response.content,
                    }
                )

                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "OBSERVATION:\n"
                            + json.dumps(
                                observation,
                                ensure_ascii=False,
                            )
                        ),
                    }
                )

                continue

            # =================================================
            # DIRECT JSON ARRAY = FINAL
            # =================================================

            if isinstance(action, list):
                self.logger.event(
                    "agent_final",
                    {
                        "stage": self.stage,
                        "step": step,
                        "answer": action,
                        "format": "direct_json_array",
                    },
                )

                return action

            # -------------------------------------------------
            # Primitive values are invalid
            # -------------------------------------------------

            if not isinstance(action, dict):
                messages.append(
                    {
                        "role": "assistant",
                        "content": response.content,
                    }
                )

                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "OBSERVATION: The response must be "
                            "either a JSON object or JSON array."
                        ),
                    }
                )

                continue

            # =================================================
            # DIRECT JSON OBJECT = FINAL
            # =================================================

            if "type" not in action:
                looks_like_tool_call = (
                    "tool" in action
                    or "arguments" in action
                )

                if looks_like_tool_call:
                    messages.append(
                        {
                            "role": "assistant",
                            "content": response.content,
                        }
                    )

                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "OBSERVATION: A tool call must "
                                'contain "type": "tool".'
                            ),
                        }
                    )

                    continue

                self.logger.event(
                    "agent_final",
                    {
                        "stage": self.stage,
                        "step": step,
                        "answer": action,
                        "format": "direct_json_object",
                    },
                )

                return action

            # -------------------------------------------------
            # Wrapped protocol
            # -------------------------------------------------

            kind = str(
                action.get("type") or ""
            ).lower()

            # =================================================
            # WRAPPED FINAL
            # =================================================

            if kind == "final":
                answer = action.get("answer")

                # Sometimes a model puts the final JSON inside
                # "answer" as a JSON-encoded string.
                if isinstance(answer, str):
                    try:
                        answer = extract_json_value(
                            answer
                        )
                    except ValueError:
                        pass

                self.logger.event(
                    "agent_final",
                    {
                        "stage": self.stage,
                        "step": step,
                        "answer": answer,
                        "format": "wrapped_final",
                    },
                )

                return answer

            # =================================================
            # UNKNOWN ACTION
            # =================================================

            if kind != "tool":
                messages.append(
                    {
                        "role": "assistant",
                        "content": response.content,
                    }
                )

                messages.append(
                    {
                        "role": "user",
                        "content": (
                            'OBSERVATION: Unknown action type. '
                            'Use "tool", "final", or return the '
                            "requested final JSON value directly."
                        ),
                    }
                )

                continue

            # =================================================
            # TOOL CALL
            # =================================================

            tool_name = str(
                action.get("tool") or ""
            )

            arguments = (
                action.get("arguments")
                or {}
            )

            if not isinstance(arguments, dict):
                arguments = {}

            try:
                result = self.tools.call(
                    tool_name,
                    arguments,
                )

                observation = {
                    "tool": tool_name,
                    "ok": True,
                    "result": result,
                }

            except Exception as exc:
                observation = {
                    "tool": tool_name,
                    "ok": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }

            self.logger.event(
                "agent_tool",
                {
                    "stage": self.stage,
                    "step": step,
                    "tool": tool_name,
                    "arguments": arguments,
                    "observation": observation,
                },
            )

            self._append_conversation(
                conversation_path,
                {
                    "step": step,
                    "role": "tool",
                    "content": observation,
                },
            )

            # -------------------------------------------------
            # Feed ONLY the accepted first tool call back
            # -------------------------------------------------
            #
            # Important:
            # response.content may have contained several tool
            # calls. Do not feed that original batched response
            # back into the conversation.
            #
            # Feed the single parsed action that we actually ran.
            # -------------------------------------------------

            messages.append(
                {
                    "role": "assistant",
                    "content": json.dumps(
                        action,
                        ensure_ascii=False,
                    ),
                }
            )

            messages.append(
                {
                    "role": "user",
                    "content": (
                        "OBSERVATION:\n"
                        + json.dumps(
                            observation,
                            ensure_ascii=False,
                        )
                        + "\n\n"
                        + (
                            "Choose the next action based on this "
                            "observation. Return at most ONE tool call."
                        )
                    ),
                }
            )

        raise RuntimeError(
            f"{self.stage} agent exceeded "
            f"max_steps={self.max_steps} "
            "without returning a final answer"
        )

    @staticmethod
    def _append_conversation(
        path: Path,
        value: dict[str, Any],
    ) -> None:

        with path.open(
            "a",
            encoding="utf-8",
        ) as f:
            f.write(
                json.dumps(
                    value,
                    ensure_ascii=False,
                )
                + "\n"
            )