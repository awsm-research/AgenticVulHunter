"""Allowlisted application operations; the model never receives a shell."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


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
        self._tools = {tool.name: tool for tool in (tools or [])}

    def names(self) -> list[str]:
        return list(self._tools)

    def describe(self) -> str:
        if not self._tools:
            return "(no tools)"

        return "\n".join(f"- {tool.schema_text()}" for tool in self._tools.values())

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> Any:
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be a JSON object")
        if name not in self._tools:
            raise KeyError(
                f"Unknown tool {name!r}; available: {', '.join(self.names())}"
            )

        return self._tools[name].handler(arguments)
