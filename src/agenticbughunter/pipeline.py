from __future__ import annotations

import hashlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .config import Config, validate_config
from .git import diff as git_diff, isolated_workspace, repo_root, resolve_default_base, resolve_ref
from .llm import OpenAICompatibleClient
from .models import Finding, PipelineResult, StageResult
from .runlog import RunLogger
from .stages import Stage1Candidates, Stage2Context, Stage3Hypotheses, Stage4Judge, Stage5Filter
from .tools.repo import RepositoryTools


def _run_id(repo: Path, base: str, head: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    digest = hashlib.sha1(f"{repo}:{base}:{head}:{stamp}".encode()).hexdigest()[:8]
    return f"{stamp}-{digest}"


class PipelineExecutionError(RuntimeError):
    def __init__(self, message: str, run_dir: Path, original: Exception):
        super().__init__(message)
        self.run_dir = run_dir
        self.original = original


class SecureReviewPipeline:
    """Five-stage project-local secure-review Git gate."""

    def __init__(self, config: Config):
        self.config = validate_config(config)

    def run(self, repo: str | Path = ".", *, base: str | None = None, head: str = "HEAD") -> PipelineResult:
        source_repo = repo_root(repo)
        head_sha = resolve_ref(source_repo, head)
        selected_base = base or resolve_default_base(source_repo, head=head)
        base_sha = resolve_ref(source_repo, selected_base)

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

        try:
            diff_text = git_diff(source_repo, base_sha, head_sha)
            logger.write_text(run_dir / "review.diff", diff_text)
            if not diff_text.strip():
                result = PipelineResult(run_id, "pass", [], [], str(run_dir), [])
                logger.write_json(run_dir / "comments.json", [])
                logger.write_json(run_dir / "result.json", result.to_dict())
                logger.info("COMPLETED pipeline", status="pass", reason="empty_diff_between_distinct_commits")
                return result

            with isolated_workspace(
                source_repo,
                head_sha,
                enabled=self.config.pipeline.isolate_worktree,
                keep=self.config.pipeline.keep_worktree,
            ) as workspace:
                logger.info("workspace ready", path=str(workspace.root), isolated=workspace.temporary)
                repo_tools = RepositoryTools(workspace.root, self.config.repository, base_ref=base_sha)
                client = OpenAICompatibleClient(self.config.llm, logger)

                s1 = Stage1Candidates(self.config, client, logger, repo_tools, diff_text).timed_execute(None)
                stage_results.append(s1)
                s2 = Stage2Context(self.config, client, logger, repo_tools).timed_execute(s1.output)
                stage_results.append(s2)
                s3 = Stage3Hypotheses(self.config, client, logger).timed_execute(s2.output)
                stage_results.append(s3)
                s4 = Stage4Judge(self.config, client, logger, repo_tools).timed_execute(s3.output)
                stage_results.append(s4)
                s5 = Stage5Filter(self.config, logger).timed_execute(s4.output)
                stage_results.append(s5)

            findings = [Finding(**item) for item in s5.output["findings"]]
            comments = list(s5.output["comments"])
            blocked = bool(findings) and self.config.pipeline.block_on_findings
            status = "block" if blocked else "pass"
            result = PipelineResult(run_id, status, findings, comments, str(run_dir), stage_results)
            logger.write_json(run_dir / "result.json", result.to_dict())
            logger.info("COMPLETED pipeline", status=status, findings=len(findings), comments=len(comments))
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
            logger.error("FAILED pipeline", error_type=type(exc).__name__, error=str(exc), completed_stages=len(stage_results))
            raise PipelineExecutionError(
                f"AgenticBugHunter pipeline failed: {type(exc).__name__}: {exc}",
                run_dir,
                exc,
            ) from exc
        finally:
            logger.close()
