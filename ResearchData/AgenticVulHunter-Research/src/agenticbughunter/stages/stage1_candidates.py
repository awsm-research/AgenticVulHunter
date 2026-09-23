from __future__ import annotations

import json
from typing import Any

from ..config import Config
from ..diff import (
    annotate_diff,
    changed_line_map,
    parse_annotated_diff,
    parse_unified_diff,
)
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
        *,
        input_format: str = "unified",
        prompt_name: str = "stage1_candidates.md",
        added_only: bool = False,
        raw_diff_text: str | None = None,
    ):
        self.config = config
        self.client = client
        self._logger = logger
        self.repo_tools = repo_tools
        self.diff_text = diff_text
        self.input_format = input_format
        self.prompt_name = prompt_name
        self.added_only = added_only
        self.raw_diff_text = raw_diff_text
        if self.input_format not in {"unified", "annotated"}:
            raise ValueError("Stage 1 input_format must be unified or annotated")

    def _parsed(self):
        return (
            parse_annotated_diff(self.diff_text)
            if self.input_format == "annotated"
            else parse_unified_diff(self.diff_text)
        )

    def _annotated(self) -> str:
        return (
            self.diff_text
            if self.input_format == "annotated"
            else annotate_diff(self.diff_text)
        )

    def _input_chunks(self, annotated: str, target: int) -> list[str]:
        """Split only at prepared A/D/C record boundaries; preserve the full artifact."""
        chunks: list[str] = []
        current: list[str] = []
        size = 0
        for line in annotated.splitlines(keepends=True):
            if current and size + len(line) > target:
                chunks.append("".join(current))
                current, size = [], 0
            current.append(line)
            size += len(line)
        if current:
            chunks.append("".join(current))
        return chunks or [annotated]

    @staticmethod
    def _normalise_answer(raw: Any) -> list[Any]:
        if isinstance(raw, str):
            raw = json.loads(raw)
        if isinstance(raw, dict) and isinstance(raw.get("candidates"), list):
            raw = raw["candidates"]
        elif (
            isinstance(raw, dict)
            and raw.get("filepath")
            and raw.get("changed_line") is not None
        ):
            raw = [raw]
        if not isinstance(raw, list):
            raise TypeError(
                "Stage 1 final answer must be a JSON array of candidates; "
                f"received {type(raw).__name__}: {raw!r}"
            )
        return raw

    @staticmethod
    def _proposal_score(item: Any) -> float:
        if not isinstance(item, dict):
            return 0.0
        try:
            return float(item.get("security_relevance_score", 0.0))
        except (TypeError, ValueError):
            return 0.0

    def _diff_context(
        self, filepath: str, line: int, change_type: str, radius: int = 8
    ) -> str:
        values = [item for item in self._parsed() if item.filepath == filepath]
        target = None
        for idx, item in enumerate(values):
            number = item.new_line if change_type == "A" else item.old_line
            if item.kind == change_type and number == line:
                target = idx
                break
        if target is None:
            return ""
        start = max(0, target - radius)
        end = min(len(values), target + radius + 1)
        out: list[str] = []
        for item in values[start:end]:
            number = item.new_line if item.kind != "D" else item.old_line
            out.append(f"[{item.kind},{item.filepath},{number}] {item.text}")
        return "\n".join(out)

    def execute(self, _value: Any = None) -> list[dict[str, Any]]:
        stage_dir = self._logger.stage_dir(self.name)
        parsed = self._parsed()
        annotated = self._annotated()
        unbounded_research = (
            self.input_format == "annotated"
            and self.prompt_name == "stage1_candidates_research.md"
        )

        self._logger.write_text(stage_dir / "annotated.diff", annotated)
        if self.raw_diff_text is not None:
            self._logger.write_text(stage_dir / "raw.diff", self.raw_diff_text)
        elif self.input_format == "unified":
            self._logger.write_text(stage_dir / "raw.diff", self.diff_text)

        allowed = {
            key: statement
            for key, statement in changed_line_map(parsed).items()
            if statement.strip() and (not self.added_only or key[2] == "A")
        }
        if not allowed:
            self._logger.write_json(stage_dir / "output.json", [])
            return []

        system = prompt(self.prompt_name).replace(
            "__MAX_CANDIDATES__",
            str(self.config.pipeline.max_candidates),
        )

        registry = self.repo_tools.registry()
        fixed_overhead = len(system) + len(PROTOCOL) + len(registry.describe()) + 4_000
        chunk_target = max(
            1_000,
            min(60_000, self.config.llm.max_input_chars - fixed_overhead),
        )
        chunks = self._input_chunks(annotated, chunk_target)
        raw: list[Any] = []
        degraded = 0
        for index, chunk in enumerate(chunks, 1):
            item_dir = (
                stage_dir if len(chunks) == 1 else stage_dir / f"batch-{index:03d}"
            )
            item_dir.mkdir(parents=True, exist_ok=True)
            self._logger.write_text(item_dir / "annotated_input.diff", chunk)
            suffix = (
                "Follow the Stage-1 instructions above. Return ONLY the JSON array. "
                if self.input_format == "annotated"
                and self.prompt_name == "stage1_candidates_research.md"
                else f"Return a JSON ARRAY of at most {self.config.pipeline.max_candidates} candidates. "
            )
            user = (
                f"ANNOTATED DIFF BATCH {index} OF {len(chunks)}:\n\n{chunk}\n\n{suffix}"
                "The statement field must be a valid JSON string with embedded quotes escaped."
            )
            agent = AgentRunner(
                self.client,
                registry,
                self._logger,
                stage=f"{self.name}:batch-{index}",
                max_steps=self.config.agents.stage1_max_steps,
                artifact_dir=item_dir,
            )
            try:
                proposed = self._normalise_answer(agent.run(system, user))
                eligible = False
                for item in proposed:
                    if not isinstance(item, dict):
                        continue
                    try:
                        key = (
                            str(item.get("filepath") or "").rstrip("\t").strip(),
                            int(item.get("changed_line")),
                            str(
                                item.get("change_type") or item.get("kind") or "A"
                            ).upper(),
                        )
                    except (TypeError, ValueError):
                        continue
                    eligible = eligible or key in allowed
                if proposed and not eligible:
                    raise ValueError(
                        "No proposed candidate matched an exact eligible [A,...] record"
                    )
                raw.extend(proposed)
            except (
                AgentOutputError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ) as exc:
                degraded += 1
                error = {
                    "stage": self.name,
                    "batch": index,
                    "status": "degraded_zero_candidates",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
                self._logger.write_json(item_dir / "model_output_error.json", error)
                self._logger.event("stage1_batch_degraded", error)

        raw.sort(key=self._proposal_score, reverse=True)

        out: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str]] = set()
        for item in raw:
            if not isinstance(item, dict):
                continue
            path = str(item.get("filepath") or "").rstrip("\t").strip()
            if not path:
                continue
            try:
                line = int(item.get("changed_line"))
            except (TypeError, ValueError):
                continue
            change_type = str(
                item.get("change_type") or item.get("kind") or "A"
            ).upper()
            if change_type not in {"A", "D"}:
                continue
            if self.added_only and change_type != "A":
                continue
            key = (path, line, change_type)
            if key not in allowed or key in seen:
                continue

            statement = allowed[key]
            try:
                score = float(item.get("security_relevance_score", 0.0))
            except (TypeError, ValueError):
                score = 0.0
            score = min(1.0, max(0.0, score))

            candidate = Candidate(
                candidate_id=f"candidate-{len(out) + 1}",
                filepath=path,
                changed_line=line,
                statement=statement,
                change_type=change_type,
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
                        "revision": "base" if change_type == "D" else "head",
                    }
                )
                candidate.code_context = str(context.get("text") or "")
            except (FileNotFoundError, RuntimeError, ValueError):
                candidate.code_context = self._diff_context(path, line, change_type)

            out.append(candidate.to_dict())
            seen.add(key)
            if (
                not unbounded_research
                and len(out) >= self.config.pipeline.max_candidates
            ):
                break

        self._logger.event(
            "candidate_validation",
            {
                "proposed": len(raw),
                "retained": len(out),
                "input_format": self.input_format,
                "added_only": self.added_only,
                "prompt": self.prompt_name,
                "candidate_limit": (
                    None if unbounded_research else self.config.pipeline.max_candidates
                ),
                "batches": len(chunks),
                "degraded_batches": degraded,
            },
        )
        self._logger.write_json(
            stage_dir / "status.json",
            {
                "status": "degraded" if degraded else "complete",
                "batches": len(chunks),
                "degraded_batches": degraded,
                "retained_candidates": len(out),
            },
        )
        self._logger.write_json(stage_dir / "output.json", out)
        return out
