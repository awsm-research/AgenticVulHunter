from __future__ import annotations

import json
from typing import Any

from .base import Stage
from ..config import Config
from ..diff import changed_line_map, annotate_diff, parse_unified_diff
from ..llm import AgentRunner, OpenAICompatibleClient
from ..models import Candidate
from ..resources import prompt
from ..runlog import RunLogger
from ..tools.repo import RepositoryTools


class Stage1Candidates(Stage):
    name = "stage1_candidates"

    def __init__(
        self,
        config: Config,
        client: OpenAICompatibleClient,
        logger: RunLogger,
        repo_tools: RepositoryTools,
        diff_text: str,
    ):
        self.config = config
        self.client = client
        self._logger = logger
        self.repo_tools = repo_tools
        self.diff_text = diff_text

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
            number = (
                item.new_line
                if change_type == "A"
                else item.old_line
            )

            if (
                item.kind == change_type
                and number == line
            ):
                target = idx
                break

        if target is None:
            return ""

        start = max(0, target - radius)
        end = min(len(values), target + radius + 1)

        out: list[str] = []

        for item in values[start:end]:
            number = (
                item.new_line
                if item.kind != "D"
                else item.old_line
            )

            out.append(
                f"[{item.kind},{item.filepath},{number}] {item.text}"
            )

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

        system = prompt(
            "stage1_candidates.md"
        ).replace(
            "__MAX_CANDIDATES__",
            str(self.config.pipeline.max_candidates),
        )

        user = (
            "ANNOTATED DIFF:\n\n"
            + annotated
            + "\n\n"
            + "Return a JSON ARRAY of at most "
            + str(self.config.pipeline.max_candidates)
            + " candidates. "
            + "The statement field must be a valid JSON string "
            + "with embedded quotes properly escaped."
        )

        agent = AgentRunner(
            self.client,
            self.repo_tools.registry(),
            self._logger,
            stage=self.name,
            max_steps=self.config.agents.stage1_max_steps,
            artifact_dir=stage_dir,
        )

        raw = agent.run(
            system,
            user,
        )

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
        if (
            isinstance(raw, dict)
            and isinstance(raw.get("candidates"), list)
        ):
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

            path = str(
                item.get("filepath") or ""
            )

            if not path:
                continue

            try:
                line = int(
                    item.get("changed_line")
                )
            except (TypeError, ValueError):
                continue

            change_type = str(
                item.get("change_type")
                or item.get("kind")
                or "A"
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
                function_name=str(
                    item.get("function_name") or ""
                ),
                operation_type=str(
                    item.get("operation_type") or ""
                ),
                selection_reason=str(
                    item.get("selection_reason") or ""
                ),
                security_relevance_score=score,
            )

            try:
                context = self.repo_tools.file_context(
                    {
                        "path": path,
                        "line": line,
                        "radius": self.config.repository.context_radius,
                        "revision": (
                            "base"
                            if change_type == "D"
                            else "head"
                        ),
                    }
                )

                candidate.code_context = str(
                    context.get("text") or ""
                )

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

            out.append(
                candidate.to_dict()
            )

            seen.add(key)

            if (
                len(out)
                >= self.config.pipeline.max_candidates
            ):
                break

        self._logger.write_json(
            stage_dir / "output.json",
            out,
        )

        return out