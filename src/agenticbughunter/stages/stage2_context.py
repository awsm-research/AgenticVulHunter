from __future__ import annotations

import json
from typing import Any

from .base import Stage
from ..config import Config
from ..llm import AgentRunner, ChatClient
from ..resources import prompt
from ..runlog import RunLogger
from ..tools.repo import RepositoryTools


_IMMUTABLE = ("candidate_id", "filepath", "changed_line", "statement", "change_type")


class Stage2Context(Stage):
    name = "stage2_context"

    def __init__(self, config: Config, client: ChatClient, logger: RunLogger, repo_tools: RepositoryTools):
        self.config = config
        self.client = client
        self._logger = logger
        self.repo_tools = repo_tools

    def execute(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        stage_dir = self._logger.stage_dir(self.name)
        self._logger.write_json(stage_dir / "input.json", candidates)
        results: list[dict[str, Any]] = []
        system = prompt("stage2_context.md")

        for candidate in candidates:
            cid = str(candidate["candidate_id"])
            item_dir = stage_dir / cid
            item_dir.mkdir(parents=True, exist_ok=True)
            self._logger.write_json(item_dir / "input.json", candidate)
            agent = AgentRunner(
                self.client,
                self.repo_tools.registry(),
                self._logger,
                stage=f"{self.name}:{cid}",
                max_steps=self.config.agents.stage2_max_steps,
                artifact_dir=item_dir,
            )
            answer = agent.run(system, "CANDIDATE INPUT:\n" + json.dumps(candidate, ensure_ascii=False, indent=2))
            if not isinstance(answer, dict):
                raise ValueError(f"Stage 2 {cid} final answer must be a JSON object")
            for field in _IMMUTABLE:
                if field in answer and answer[field] != candidate[field]:
                    raise ValueError(f"Stage 2 changed immutable field {field} for {cid}")
            enriched = dict(candidate)
            enriched.update(answer)
            for field in _IMMUTABLE:
                enriched[field] = candidate[field]
            results.append(enriched)
            self._logger.write_json(item_dir / "output.json", enriched)

        self._logger.write_json(stage_dir / "output.json", results)
        return results
