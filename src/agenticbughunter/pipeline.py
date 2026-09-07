from __future__ import annotations

import hashlib
import platform
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config, validate_config
from .git import diff as git_diff
from .git import (
    isolated_workspace,
    merge_base,
    repo_root,
    resolve_default_base,
    resolve_ref,
)
from .llm import ChatClient, create_client
from .models import Finding, PipelineResult, StageResult
from .resources import prompt
from .runlog import RunLogger
from .stages import (
    Stage1Candidates,
    Stage2Context,
    Stage3Hypotheses,
    Stage4Judge,
    Stage5Filter,
)
from .tools.repo import RepositoryTools


def _run_id(repo: Path, base: str, head: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    digest = hashlib.sha1(f"{repo}:{base}:{head}:{stamp}".encode()).hexdigest()[:8]
    return f"{stamp}-{digest}"


class PipelineExecutionError(RuntimeError):
    def __init__(self, message: str, run_dir: Path, original: Exception):
        super().__init__(message)
        self.run_dir = run_dir
        self.original = original


class SecureReviewPipeline:
    """Five-stage project-local secure-review Git gate."""

    def __init__(
        self,
        config: Config,
        progress: Callable[[str, dict[str, Any]], None] | None = None,
        *,
        client: ChatClient | None = None,
    ):
        self.config = validate_config(config)
        self.progress = progress
        self.client = client

    def _emit(self, event: str, **payload: Any) -> None:
        if self.progress is None:
            return
        try:
            self.progress(event, payload)
        except Exception:
            # Presentation must never change secure-review behaviour.
            return

    def _execute_stage(self, index: int, stage, value: Any) -> StageResult:
        self._emit("stage_started", stage=stage.name, index=index)
        active_logger = getattr(self, "_active_logger", None)
        if active_logger is not None:
            active_logger.event("stage_started", {"stage": stage.name, "index": index})
        try:
            result = stage.timed_execute(value)
        except Exception as exc:
            self._emit(
                "stage_failed",
                stage=stage.name,
                index=index,
                error=f"{type(exc).__name__}: {exc}",
            )
            if active_logger is not None:
                active_logger.event(
                    "stage_failed",
                    {
                        "stage": stage.name,
                        "index": index,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )
            raise
        self._emit(
            "stage_completed",
            stage=stage.name,
            index=index,
            duration_ms=result.duration_ms,
            output=result.output,
        )
        if active_logger is not None:
            active_logger.event(
                "stage_completed",
                {
                    "stage": stage.name,
                    "index": index,
                    "duration_ms": result.duration_ms,
                },
            )
        return result

    def run(
        self, repo: str | Path = ".", *, base: str | None = None, head: str = "HEAD"
    ) -> PipelineResult:
        source_repo = repo_root(repo)
        head_sha = resolve_ref(source_repo, head)
        selected_base = base or resolve_default_base(source_repo, head=head)
        base_sha = resolve_ref(source_repo, selected_base)
        diff_base_sha = merge_base(source_repo, base_sha, head_sha)

        run_id = _run_id(source_repo, base_sha, head_sha)
        run_dir = source_repo / ".agenticbughunter" / "runs" / run_id
        logger = RunLogger(run_dir)
        self._active_logger = logger
        stage_results: list[StageResult] = []
        logger.info(
            "START pipeline",
            repo=str(source_repo),
            base=selected_base,
            base_sha=base_sha,
            head=head,
            head_sha=head_sha,
            run_id=run_id,
        )
        logger.write_json(run_dir / "config.json", asdict(self.config))
        logger.write_json(
            run_dir / "provenance.json",
            {
                "application_version": __version__,
                "python_version": platform.python_version(),
                "base_sha": base_sha,
                "diff_base_sha": diff_base_sha,
                "head_sha": head_sha,
                "provider": self.config.llm.provider,
                "model": self.config.llm.model,
                "client_type": type(self.client).__name__
                if self.client is not None
                else "HTTPChatClient",
                "judge_policy": "application_relationship_contradiction_caps_v1",
                "prompt_sha256": {
                    name: hashlib.sha256(prompt(name).encode()).hexdigest()
                    for name in (
                        "stage1_candidates.md",
                        "stage2_context.md",
                        "stage3_hypotheses.md",
                        "stage4_judge.md",
                    )
                },
            },
        )
        self._emit(
            "pipeline_started",
            repo=str(source_repo),
            base=selected_base,
            head=head,
            run_id=run_id,
            model=self.config.llm.model,
            threshold=self.config.pipeline.confidence_threshold,
        )

        try:
            diff_text = git_diff(source_repo, base_sha, head_sha)
            logger.write_text(run_dir / "review.diff", diff_text)
            if not diff_text.strip():
                result = PipelineResult(run_id, "pass", [], [], str(run_dir), [])
                logger.write_json(run_dir / "comments.json", [])
                logger.write_json(run_dir / "result.json", result.to_dict())
                logger.info(
                    "COMPLETED pipeline",
                    status="pass",
                    reason="empty_diff_between_distinct_commits",
                )
                self._emit("empty_diff")
                return result

            with isolated_workspace(
                source_repo,
                head_sha,
                enabled=self.config.pipeline.isolate_worktree,
                keep=self.config.pipeline.keep_worktree,
            ) as workspace:
                logger.info(
                    "workspace ready",
                    path=str(workspace.root),
                    isolated=workspace.temporary,
                )
                self._emit(
                    "workspace_ready",
                    path=str(workspace.root),
                    isolated=workspace.temporary,
                )
                repo_tools = RepositoryTools(
                    workspace.root, self.config.repository, base_ref=diff_base_sha
                )
                client = (
                    self.client
                    if self.client is not None
                    else create_client(self.config.llm, logger)
                )

                s1 = self._execute_stage(
                    1,
                    Stage1Candidates(
                        self.config, client, logger, repo_tools, diff_text
                    ),
                    None,
                )
                stage_results.append(s1)
                s2 = self._execute_stage(
                    2, Stage2Context(self.config, client, logger, repo_tools), s1.output
                )
                stage_results.append(s2)
                s3 = self._execute_stage(
                    3, Stage3Hypotheses(self.config, client, logger), s2.output
                )
                stage_results.append(s3)
                s4 = self._execute_stage(
                    4, Stage4Judge(self.config, client, logger, repo_tools), s3.output
                )
                stage_results.append(s4)
                s5 = self._execute_stage(
                    5, Stage5Filter(self.config, logger), s4.output
                )
                stage_results.append(s5)

            findings = [Finding(**item) for item in s5.output["findings"]]
            comments = list(s5.output["comments"])
            blocked = bool(findings) and self.config.pipeline.block_on_findings
            status = "block" if blocked else "pass"
            result = PipelineResult(
                run_id, status, findings, comments, str(run_dir), stage_results
            )
            logger.write_json(run_dir / "result.json", result.to_dict())
            logger.info(
                "COMPLETED pipeline",
                status=status,
                findings=len(findings),
                comments=len(comments),
            )
            return result
        except Exception as exc:
            failure = {
                "run_id": run_id,
                "status": "error",
                "findings": [],
                "comments": [],
                "run_dir": str(run_dir),
                "stages": [asdict(s) for s in stage_results],
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
            logger.write_json(run_dir / "result.json", failure)
            logger.error(
                "FAILED pipeline",
                error_type=type(exc).__name__,
                error=str(exc),
                completed_stages=len(stage_results),
            )
            raise PipelineExecutionError(
                f"AgenticBugHunter pipeline failed: {type(exc).__name__}: {exc}",
                run_dir,
                exc,
            ) from exc
        finally:
            logger.close()
            self._active_logger = None
