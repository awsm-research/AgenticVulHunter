"""Main four-stage AgenticVulHunter pipeline.

The pipeline reads the Git diff at runtime, runs Stages 1 to 4, and then applies
the threshold given in the CLI to the Stage 4 validation score.
"""

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
from .git import merge_base, repo_root, resolve_default_base, resolve_ref
from .llm import ChatClient, create_client
from .models import Finding, PipelineResult, StageResult
from .resources import prompt
from .runlog import RunLogger
from .stages import Stage1Candidates, Stage2Context, Stage3Hypotheses, Stage4Judge
from .tools.repo import RepositoryTools


def _run_id(repo: Path, base: str, head: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    digest = hashlib.sha1(f"{repo}:{base}:{head}:{stamp}".encode()).hexdigest()[:8]
    return f"{stamp}-{digest}"


def _finalize_stage4(
    stage4_output: list[dict[str, Any]], threshold: float
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Keep Stage 4 findings that meet the command-line threshold."""
    if not 0.0 <= float(threshold) <= 1.0:
        raise ValueError("threshold must be between 0.0 and 1.0")

    findings: list[Finding] = []
    for item in stage4_output:
        assessments = item.get("cwe_assessments")
        if not isinstance(assessments, list):
            continue

        valid: list[dict[str, Any]] = []
        for assessment in assessments:
            if not isinstance(assessment, dict):
                continue
            try:
                score = float(assessment.get("score", 0.0))
            except (TypeError, ValueError):
                continue
            row = dict(assessment)
            row["score"] = score
            valid.append(row)

        if not valid:
            continue

        best = max(valid, key=lambda row: float(row.get("score", 0.0)))
        score = float(best.get("score", 0.0))
        comment = str(best.get("review_comment") or "").strip()
        if score < threshold or not comment:
            continue

        findings.append(
            Finding(
                candidate_id=str(item.get("candidate_id") or ""),
                filepath=str(item.get("filepath") or ""),
                changed_line=int(item.get("changed_line") or 0),
                statement=str(item.get("statement") or ""),
                cwe_id=str(best.get("cwe_id") or ""),
                cwe_name=str(best.get("cwe_name") or ""),
                final_score=score,
                review_comment=comment,
                assessment=best,
            )
        )

    findings.sort(key=lambda finding: finding.final_score, reverse=True)
    comments = [
        {
            "filepath": finding.filepath,
            "line_number": finding.changed_line,
            "change_type": "A",
            "review_comment": finding.review_comment,
            "line_snippet": finding.statement,
            "vuln_type": [finding.cwe_id],
            "judge_final_score": finding.final_score,
        }
        for finding in findings
    ]
    return findings, comments


class PipelineExecutionError(RuntimeError):
    def __init__(self, message: str, run_dir: Path, original: Exception):
        super().__init__(message)
        self.run_dir = run_dir
        self.original = original


class SecureReviewPipeline:
    """Four-stage AgenticVulHunter runtime pipeline."""

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
            return

    def _stage(self, index: int, stage, value: Any) -> StageResult:
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
        )
        return result

    def run(
        self,
        repo: str | Path = ".",
        *,
        base: str | None = None,
        head: str = "HEAD",
        threshold: float = 0.80,
    ) -> PipelineResult:
        source_repo = repo_root(repo)
        head_sha = resolve_ref(source_repo, head)
        selected_base = base or resolve_default_base(source_repo, head=head)
        base_sha = resolve_ref(source_repo, selected_base)
        diff_base_sha = merge_base(source_repo, base_sha, head_sha)

        run_id = _run_id(source_repo, base_sha, head_sha)
        self._emit(
            "review_started",
            repo=str(source_repo),
            base=base_sha,
            head=head_sha,
            threshold=threshold,
            model=self.config.llm.model,
        )
        run_dir = source_repo / ".agenticvulhunter" / "runs" / run_id
        logger = RunLogger(run_dir)
        stage_results: list[StageResult] = []

        logger.info(
            "START pipeline",
            repo=str(source_repo),
            base=selected_base,
            head=head,
            run_id=run_id,
            threshold=threshold,
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
                "model": self.config.llm.model,
                "threshold": threshold,
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

        try:
            diff_text = git_diff(source_repo, base_sha, head_sha)
            logger.write_text(run_dir / "review.diff", diff_text)
            if not diff_text.strip():
                result = PipelineResult(run_id, "pass", [], [], str(run_dir), [])
                logger.write_json(run_dir / "result.json", result.to_dict())
                return result

            repo_tools = RepositoryTools(
                source_repo,
                self.config.repository,
                base_ref=diff_base_sha,
            )
            client = self.client or create_client(self.config.llm, logger)

            stage1 = self._stage(
                1,
                Stage1Candidates(
                    self.config,
                    client,
                    logger,
                    repo_tools,
                    diff_text,
                ),
                None,
            )
            stage_results.append(stage1)

            stage2 = self._stage(
                2,
                Stage2Context(
                    self.config,
                    client,
                    logger,
                    repo_tools,
                ),
                stage1.output,
            )
            stage_results.append(stage2)

            stage3 = self._stage(
                3,
                Stage3Hypotheses(self.config, client, logger),
                stage2.output,
            )
            stage_results.append(stage3)

            stage4 = self._stage(
                4,
                Stage4Judge(self.config, client, logger),
                stage3.output,
            )
            stage_results.append(stage4)

            findings, comments = _finalize_stage4(stage4.output, threshold)
            result = PipelineResult(
                run_id,
                "pass",
                findings,
                comments,
                str(run_dir),
                stage_results,
            )
            logger.write_json(run_dir / "comments.json", comments)
            logger.write_json(run_dir / "result.json", result.to_dict())
            logger.info(
                "COMPLETED pipeline",
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
                "stages": [asdict(stage) for stage in stage_results],
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
            logger.write_json(run_dir / "result.json", failure)
            raise PipelineExecutionError(
                f"AgenticVulHunter pipeline failed: {type(exc).__name__}: {exc}",
                run_dir,
                exc,
            ) from exc
        finally:
            logger.close()
