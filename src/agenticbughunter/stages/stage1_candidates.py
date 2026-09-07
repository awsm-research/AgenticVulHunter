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
        self._logger = logger
        self.repo_tools = repo_tools
        self.diff_text = diff_text

    @staticmethod
    def _input_chunks(annotated: str, target: int) -> list[str]:
        """Split at annotated record boundaries without dropping any changed line."""
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
        self,
        filepath: str,
        line: int,
        change_type: str,
        radius: int = 8,
    ) -> str:
        values = [
            item
            for item in parse_unified_diff(self.diff_text)
            if item.filepath == filepath
        ]

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

    def execute(
        self,
        _value: Any = None,
    ) -> list[dict[str, Any]]:

        stage_dir = self._logger.stage_dir(self.name)

        parsed = parse_unified_diff(self.diff_text)
        annotated = annotate_diff(self.diff_text)

        self._logger.write_text(
            stage_dir / "annotated.diff",
            annotated,
        )

        self._logger.write_text(
            stage_dir / "raw.diff",
            self.diff_text,
        )

        # Only actual non-whitespace changed lines can become candidates.
        allowed = {
            key: statement
            for key, statement in changed_line_map(parsed).items()
            if statement.strip()
        }

        # Nothing meaningful changed -> no reason to call the LLM.
        if not allowed:
            self._logger.write_json(
                stage_dir / "output.json",
                [],
            )
            return []

        system = prompt("stage1_candidates.md").replace(
            "__MAX_CANDIDATES__",
            str(self.config.pipeline.max_candidates),
        )

        registry = self.repo_tools.registry()
        fixed_overhead = len(system) + len(PROTOCOL) + len(registry.describe()) + 4_000
        chunk_target = max(
            1_000, min(60_000, self.config.llm.max_input_chars - fixed_overhead)
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
            user = (
                f"ANNOTATED DIFF BATCH {index} OF {len(chunks)}:\n\n{chunk}\n\n"
                f"Return a JSON ARRAY of at most {self.config.pipeline.max_candidates} candidates. "
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
                eligible = any(
                    isinstance(item, dict)
                    and (
                        str(item.get("filepath") or "").rstrip("\t").strip(),
                        int(item.get("changed_line") or 0),
                        str(item.get("change_type") or item.get("kind") or "A").upper(),
                    )
                    in allowed
                    for item in proposed
                )
                if proposed and not eligible:
                    raise ValueError(
                        "No proposed candidate matched an exact changed-line record"
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

        # ---------------------------------------------------------
        # Normalize valid Stage-1 output shapes
        # ---------------------------------------------------------

        # Wrapped JSON may occasionally come back as a string.
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                pass

        # Accept:
        # {
        #     "candidates": [...]
        # }
        if isinstance(raw, dict) and isinstance(raw.get("candidates"), list):
            raw = raw["candidates"]

        # Accept a genuinely returned single candidate.
        elif (
            isinstance(raw, dict)
            and raw.get("filepath")
            and raw.get("changed_line") is not None
        ):
            raw = [raw]

        if not isinstance(raw, list):
            raise ValueError(
                "Stage 1 final answer must be a JSON array of candidates; "
                f"received {type(raw).__name__}: {raw!r}"
            )

        # ---------------------------------------------------------
        # Deterministic candidate validation
        # ---------------------------------------------------------

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

            key = (
                path,
                line,
                change_type,
            )

            # Agent can read anywhere in the repo,
            # but the candidate itself must be an actual changed line.
            if key not in allowed:
                continue

            if key in seen:
                continue

            # Always use the canonical statement from Git diff.
            statement = allowed[key]

            try:
                score = float(
                    item.get(
                        "security_relevance_score",
                        0.0,
                    )
                )
            except (TypeError, ValueError):
                score = 0.0

            score = min(
                1.0,
                max(0.0, score),
            )

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
                        "revision": ("base" if change_type == "D" else "head"),
                    }
                )

                candidate.code_context = str(context.get("text") or "")

            except (
                FileNotFoundError,
                RuntimeError,
                ValueError,
            ):
                candidate.code_context = self._diff_context(
                    path,
                    line,
                    change_type,
                )

            out.append(candidate.to_dict())

            seen.add(key)

            if len(out) >= self.config.pipeline.max_candidates:
                break

        self._logger.event(
            "candidate_validation",
            {
                "proposed": len(raw),
                "retained": len(out),
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
        self._logger.write_json(
            stage_dir / "output.json",
            out,
        )

        return out
