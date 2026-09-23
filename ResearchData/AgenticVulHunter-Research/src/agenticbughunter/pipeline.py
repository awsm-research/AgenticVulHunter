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
        try:
            result = stage.timed_execute(value)
        except Exception as exc:
            self._emit(
                "stage_failed",
                stage=stage.name,
                index=index,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise
        self._emit(
            "stage_completed",
            stage=stage.name,
            index=index,
            duration_ms=result.duration_ms,
            output=result.output,
        )
        return result

    def run_annotated(
        self,
        repo: str | Path,
        *,
        annotated_diff: str,
        raw_diff: str | None = None,
        diff_id: str = "",
    ) -> PipelineResult:
        """Run the paper experiment directly on a prepared A/D/C Stage-1 diff.

        This mode deliberately does not reconstruct the review diff from Git and
        does not create an isolated worktree.  Harbor/SCRBench prepares the
        working repository; Stage 1 receives the frozen annotated diff while
        later stages inspect that exact working tree.
        """
        source_repo = Path(repo).expanduser().resolve()
        if not source_repo.is_dir():
            raise ValueError(
                f"Repository knowledge-base path is not a directory: {source_repo}"
            )
        label = diff_id or "annotated"
        run_id = _run_id(source_repo, label, "current-workspace")
        run_dir = source_repo / ".agenticbughunter" / "runs" / run_id
        logger = RunLogger(run_dir)
        stage_results: list[StageResult] = []
        logger.info(
            "START research pipeline",
            repo=str(source_repo),
            diff_id=diff_id,
            head_sha=None,
            run_id=run_id,
            stage1_input="prepared_adc_annotated_diff",
        )
        logger.write_json(run_dir / "config.json", asdict(self.config))
        logger.write_text(run_dir / "review.annotated.diff", annotated_diff)
        if raw_diff is not None:
            logger.write_text(run_dir / "review.raw.diff", raw_diff)
        logger.write_json(
            run_dir / "provenance.json",
            {
                "application_version": __version__,
                "python_version": platform.python_version(),
                "mode": "research_annotated_diff",
                "diff_id": diff_id,
                "head_sha": None,
                "stage1_input": "frozen_precomputed_A_D_C_annotations",
                "stage1_prompt": "stage1_candidates_research.md",
                "stage1_candidate_policy": "added_lines_only_evidence_supported",
                "repository_mode": "current_working_tree_no_isolation",
                "provider": self.config.llm.provider,
                "model": self.config.llm.model,
                "judge_policy": "research_mean_of_five_no_caps_v1",
                "prompt_sha256": {
                    name: hashlib.sha256(prompt(name).encode()).hexdigest()
                    for name in (
                        "stage1_candidates_research.md",
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
            base="prepared-annotated-diff",
            head="working-tree",
            run_id=run_id,
            model=self.config.llm.model,
            threshold=self.config.pipeline.confidence_threshold,
        )

        try:
            if not annotated_diff.strip():
                raise ValueError("Prepared annotated diff is empty")
            # The supplied A/D/C artifact defines the change. The current
            # workspace is only a read-only knowledge base; do not consult Git.
            repo_tools = RepositoryTools(
                source_repo,
                self.config.repository,
                base_ref=None,
                use_git_index=False,
            )
            client = (
                self.client
                if self.client is not None
                else create_client(self.config.llm, logger)
            )

            s1 = self._execute_stage(
                1,
                Stage1Candidates(
                    self.config,
                    client,
                    logger,
                    repo_tools,
                    annotated_diff,
                    input_format="annotated",
                    prompt_name="stage1_candidates_research.md",
                    added_only=True,
                    raw_diff_text=raw_diff,
                ),
                None,
            )
            stage_results.append(s1)
            s2 = self._execute_stage(
                2,
                Stage2Context(
                    self.config,
                    client,
                    logger,
                    repo_tools,
                    skip=self.config.pipeline.skip_stage2,
                ),
                s1.output,
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
            s5 = self._execute_stage(5, Stage5Filter(self.config, logger), s4.output)
            stage_results.append(s5)

            findings = [Finding(**item) for item in s5.output["findings"]]
            comments = list(s5.output["comments"])
            blocked = bool(findings) and self.config.pipeline.block_on_findings
            status = "block" if blocked else "pass"
            result = PipelineResult(
                run_id, status, findings, comments, str(run_dir), stage_results
            )
            logger.write_json(run_dir / "comments.json", comments)
            logger.write_json(run_dir / "result.json", result.to_dict())
            logger.info(
                "COMPLETED research pipeline",
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
                "FAILED research pipeline",
                error_type=type(exc).__name__,
                error=str(exc),
                completed_stages=len(stage_results),
            )
            raise PipelineExecutionError(
                f"AgenticVulHunter research pipeline failed: {type(exc).__name__}: {exc}",
                run_dir,
                exc,
            ) from exc
        finally:
            logger.close()

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
                "judge_policy": "research_mean_of_five_no_caps_v1",
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
                    2,
                    Stage2Context(
                        self.config,
                        client,
                        logger,
                        repo_tools,
                        skip=self.config.pipeline.skip_stage2,
                    ),
                    s1.output,
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
