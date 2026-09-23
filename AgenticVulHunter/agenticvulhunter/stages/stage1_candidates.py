"""Stage 1: select security-relevant candidate lines from the current Git diff.

This stage works at runtime and does not depend on annotated research data.
"""

from __future__ import annotations

import json
from typing import Any

from ..config import Config
from ..diff import annotate_diff, changed_line_map, parse_unified_diff
from ..llm import AgentOutputError, AgentRunner, ChatClient
from ..llm.protocol import PROTOCOL
from ..models import Candidate
from ..resources import prompt
from ..runlog import RunLogger
from ..tools.repo import RepositoryTools
from .base import Stage


class Stage1Candidates(Stage):
    name = "stage1_candidates"

    def __init__(
        self,
        config: Config,
        client: ChatClient,
        logger: RunLogger,
        repo_tools: RepositoryTools,
        diff_text: str,
    ):
        self.config = config
        self.client = client
        self.logger = logger
        self.repo_tools = repo_tools
        self.diff_text = diff_text

    @staticmethod
    def _normalise_answer(raw: Any) -> list[Any]:
        if isinstance(raw, str):
            raw = json.loads(raw)
        if isinstance(raw, dict) and isinstance(raw.get("candidates"), list):
            raw = raw["candidates"]
        elif isinstance(raw, dict) and raw.get("filepath") and raw.get("changed_line") is not None:
            raw = [raw]
        if not isinstance(raw, list):
            raise TypeError("Stage 1 must return a JSON array of candidates")
        return raw

    @staticmethod
    def _score(item: Any) -> float:
        if not isinstance(item, dict):
            return 0.0
        try:
            return float(item.get("security_relevance_score", 0.0))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _chunks(text: str, target: int) -> list[str]:
        chunks: list[str] = []
        current: list[str] = []
        size = 0
        for line in text.splitlines(keepends=True):
            if current and size + len(line) > target:
                chunks.append("".join(current))
                current, size = [], 0
            current.append(line)
            size += len(line)
        if current:
            chunks.append("".join(current))
        return chunks or [text]

    def execute(self, _value: Any = None) -> list[dict[str, Any]]:
        stage_dir = self.logger.stage_dir(self.name)
        parsed = parse_unified_diff(self.diff_text)
        annotated = annotate_diff(self.diff_text)
        self.logger.write_text(stage_dir / "annotated.diff", annotated)

        # Runtime Stage 1 only selects exact added lines from the current diff.
        allowed = {
            key: statement
            for key, statement in changed_line_map(parsed).items()
            if key[2] == "A" and statement.strip()
        }
        if not allowed:
            self.logger.write_json(stage_dir / "output.json", [])
            return []

        system = prompt("stage1_candidates.md")
        registry = self.repo_tools.registry()
        overhead = len(system) + len(PROTOCOL) + len(registry.describe()) + 4_000
        target = max(1_000, min(60_000, self.config.llm.max_input_chars - overhead))

        raw: list[Any] = []
        degraded = 0
        for index, chunk in enumerate(self._chunks(annotated, target), start=1):
            item_dir = stage_dir / f"batch-{index:03d}"
            item_dir.mkdir(parents=True, exist_ok=True)
            self.logger.write_text(item_dir / "annotated_input.diff", chunk)
            user = (
                f"ANNOTATED DIFF BATCH:\n\n{chunk}\n\n"
                "Follow the Stage 1 instructions and return only the JSON array."
            )
            agent = AgentRunner(
                self.client,
                registry,
                self.logger,
                stage=f"{self.name}:batch-{index}",
                max_steps=self.config.agents.stage1_max_steps,
                artifact_dir=item_dir,
            )
            try:
                raw.extend(self._normalise_answer(agent.run(system, user)))
            except (AgentOutputError, json.JSONDecodeError, TypeError, ValueError) as exc:
                degraded += 1
                self.logger.write_json(
                    item_dir / "model_output_error.json",
                    {"error_type": type(exc).__name__, "error": str(exc)},
                )

        raw.sort(key=self._score, reverse=True)
        output: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str]] = set()

        for item in raw:
            if not isinstance(item, dict):
                continue
            path = str(item.get("filepath") or "").strip()
            try:
                line = int(item.get("changed_line"))
            except (TypeError, ValueError):
                continue
            key = (path, line, "A")
            if key not in allowed or key in seen:
                continue

            try:
                score = float(item.get("security_relevance_score", 0.0))
            except (TypeError, ValueError):
                score = 0.0
            score = min(1.0, max(0.0, score))

            candidate = Candidate(
                candidate_id=f"candidate-{len(output) + 1}",
                filepath=path,
                changed_line=line,
                statement=allowed[key],
                change_type="A",
                function_name=str(item.get("function_name") or ""),
                operation_type=str(item.get("operation_type") or ""),
                selection_reason=str(item.get("selection_reason") or ""),
                security_relevance_score=score,
            )
            try:
                context = self.repo_tools.file_context(
                    {
                        "path": path,
                        "line": line,
                        "radius": self.config.repository.context_radius,
                        "revision": "head",
                    }
                )
                candidate.code_context = str(context.get("text") or "")
            except (FileNotFoundError, RuntimeError, ValueError):
                candidate.code_context = ""

            output.append(candidate.to_dict())
            seen.add(key)

        self.logger.event(
            "candidate_validation",
            {
                "proposed": len(raw),
                "retained": len(output),
                "degraded_batches": degraded,
            },
        )
        self.logger.write_json(stage_dir / "output.json", output)
        return output
