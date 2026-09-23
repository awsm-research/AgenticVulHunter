"""
Harbor wrapper for running the frozen AgenticVulHunter tool
against a single SCRBench task.

It:
1. Reads the SCRBench task prepared by Harbor.
2. Uploads and installs a frozen AgenticVulHunter research wheel.
3. Executes the research pipeline for the current SCRBench diff.
4. Collects the generated comments and research artifacts.
5. Makes the final comments available to the SCRBench verifier.

The prompts and vulnerability-analysis logic remain inside the frozen
AgenticVulHunter research wheel.
"""

import base64
import json
import os
import shlex
from pathlib import Path
from typing import Any

try:
    from harbor.agents.base import BaseAgent
    from harbor.environments.base import BaseEnvironment
    from harbor.models.agent.context import AgentContext
except Exception as exc:  # noqa: BLE001  # pragma: no cover
    harbor_import_error = exc
    BaseAgent = object  # type: ignore[assignment,misc]
    BaseEnvironment = Any  # type: ignore[assignment,misc]
    AgentContext = Any  # type: ignore[assignment,misc]
else:
    harbor_import_error = None

from .common import (
    LOG_ROOT,
    WRAPPER_VERSION,
    container_runtime_env,
    result_code,
    sha256,
    stderr,
    stdout,
)
from .preflight import parse_preflight, preflight_script


class AgenticVulHunterResearchAgent(BaseAgent):
    """Harbor wrapper for running the frozen AgenticVulHunter research wheel."""


    #The trajectory is coming from the tool not the harbor setup, therefore SUPPORTS_ATIF is false
    SUPPORTS_ATIF = False

    def __init__(
        self,
        *args: Any,
        wheel_path: str | None = None,
        run_timeout_sec: int | str = 7200,
        **kwargs: Any,
    ) -> None:
        if harbor_import_error is not None:
            raise RuntimeError(
                "Harbor's Python package is not importable. Run this through the "
                "Harbor environment/CLI where `harbor` is installed."
            ) from harbor_import_error

        extra_env = kwargs.pop("extra_env", None)
        super().__init__(*args, **kwargs)

        # Environment variables used inside the Harbor container
        configured_env = {**os.environ, **dict(extra_env or {})}
        self.runtime_env = container_runtime_env(configured_env)

        if not wheel_path:
            raise ValueError("wheel_path is required")

        self.wheel_path = Path(str(wheel_path)).expanduser().resolve()

        if not self.wheel_path.is_file():
            raise FileNotFoundError(
                f"Research wheel does not exist: {self.wheel_path}"
            )

        if self.wheel_path.suffix != ".whl":
            raise ValueError(
                f"Expected a .whl research artifact: {self.wheel_path}"
            )

        self.run_timeout_sec = int(run_timeout_sec)

        if self.run_timeout_sec < 1:
            raise ValueError("run_timeout_sec must be positive")

        # Save the wheel hash so the research artifact can be verified
        self.wheel_sha256 = sha256(self.wheel_path)

    @staticmethod
    def name() -> str:
        return "agenticvulhunter-research-scrbench"

    def version(self) -> str | None:
        return WRAPPER_VERSION

    async def setup(self, environment: BaseEnvironment) -> None:
        # SCRBench already prepares the repository
        del environment

    async def _exec(
        self,
        environment: BaseEnvironment,
        command: str,
        *,
        timeout_sec: int = 120,
        check: bool = True,
        env: dict[str, str] | None = None,
    ) -> Any:
        """Run a command inside the Harbor environment."""

        result = await environment.exec(
            command=command,
            timeout_sec=timeout_sec,
            env=env,
        )

        code = result_code(result)

        if check and code not in (None, 0):
            raise RuntimeError(
                f"Container command failed ({code}): {command}\n"
                f"STDOUT:\n{stdout(result)}\nSTDERR:\n{stderr(result)}"
            )

        return result

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        """Run AgenticVulHunter on the current SCRBench task."""

        # The research wheel contains the prompts and vulnerability logic
        del context

        preflight = await self._preflight(environment)
        diff_id = str(preflight["diff_id"])

        await self._record_instruction(environment, instruction)

        # Upload and install the frozen research wheel
        wheel_target = f"/workspace/{self.wheel_path.name}"

        await environment.upload_file(
            source_path=str(self.wheel_path),
            target_path=wheel_target,
        )

        install_cmd = (
            "python3 -m pip install --no-cache-dir --no-deps --force-reinstall "
            + shlex.quote(wheel_target)
            + f" > {shlex.quote(LOG_ROOT + '/install.stdout.log')}"
            + f" 2> {shlex.quote(LOG_ROOT + '/install.stderr.log')}"
        )

        await self._exec(
            environment,
            install_cmd,
            timeout_sec=300,
        )

        # Check the installed version and SCRBench diff
        preflight_cmd = (
            f"avh-research --version > "
            f"{shlex.quote(LOG_ROOT + '/version.txt')} && "
            f"avh-research diffs | grep -Fx {shlex.quote(diff_id)} "
            f"> {shlex.quote(LOG_ROOT + '/diff_id.txt')}"
        )

        await self._exec(
            environment,
            preflight_cmd,
            timeout_sec=60,
        )

        # Run the research pipeline
        run_cmd = (
            "cd /workspace/repo && "
            "avh-research experiment "
            "--repo /workspace/repo "
            f"--diff-id {shlex.quote(diff_id)} "
            "--json "
            f"> {shlex.quote(LOG_ROOT + '/cli.stdout.json')} "
            f"2> {shlex.quote(LOG_ROOT + '/cli.stderr.log')}"
        )

        run_result = await self._exec(
            environment,
            run_cmd,
            timeout_sec=self.run_timeout_sec,
            check=False,
            env=self.runtime_env,
        )

        # Keep the output files for evaluation and debugging
        await self._collect_artifacts(
            environment,
            diff_id=diff_id,
        )

        code = result_code(run_result)

        if code not in (None, 0):
            raise RuntimeError(
                "AgenticVulHunter research pipeline failed "
                f"for SCRBench task {diff_id} (exit={code}). "
                f"Artifacts were preserved under {LOG_ROOT}.\n"
                f"STDOUT:\n{stdout(run_result)}\n"
                f"STDERR:\n{stderr(run_result)}"
            )

        # Make sure comments.json exists, including an empty [] result
        await self._exec(
            environment,
            "test -s /workspace/repo/comments.json || "
            "test \"$(cat /workspace/repo/comments.json 2>/dev/null)\" = '[]'",
            timeout_sec=30,
        )

    async def _preflight(
        self,
        environment: BaseEnvironment,
    ) -> dict[str, Any]:
        """Get information about the current SCRBench task."""

        encoded = base64.b64encode(
            preflight_script(
                readiness_timeout_sec=120
            ).encode("utf-8")
        ).decode("ascii")

        python = (
            "import base64;exec(base64.b64decode("
            + repr(encoded)
            + ").decode())"
        )

        result = await self._exec(
            environment,
            "python3 -c " + shlex.quote(python),
            timeout_sec=150,
        )

        return parse_preflight(stdout(result))


    #I am saving the Instruction which is sent by SCRBench
    async def _record_instruction(
        self,
        environment: BaseEnvironment,
        instruction: str,
    ) -> None:
        encoded = base64.b64encode(
            instruction.encode("utf-8")
        ).decode("ascii")

        command = (
            f"mkdir -p {shlex.quote(LOG_ROOT)}; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > "
            f"{shlex.quote(LOG_ROOT + '/scrbench_instruction.txt')}"
        )

        await self._exec(
            environment,
            command,
            timeout_sec=30,
        )


    #After the run is complete, save the output.
    async def _collect_artifacts(
        self,
        environment: BaseEnvironment,
        *,
        diff_id: str,
    ) -> None:
    
        manifest = {
            "wrapper": "AgenticVulHunterResearchAgent",
            "wrapper_version": WRAPPER_VERSION,
            "scrbench_diff_id": diff_id,
            "wheel_name": self.wheel_path.name,
            "wheel_sha256": self.wheel_sha256,
            "analysis_owner": "agenticvulhunter-research-wheel",
            "instruction_modified": False,
        }

        manifest_b64 = base64.b64encode(
            (
                json.dumps(
                    manifest,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        ).decode("ascii")

        command = f"""
set -u
mkdir -p {shlex.quote(LOG_ROOT)}
printf %s {shlex.quote(manifest_b64)} | base64 -d > {shlex.quote(LOG_ROOT + "/wrapper_manifest.json")}

RUN_DIR=""
if test -d /workspace/repo/.agenticbughunter/runs; then
  RUN_DIR=$(ls -td /workspace/repo/.agenticbughunter/runs/* 2>/dev/null | head -1 || true)
fi

if test -n "$RUN_DIR" && test -d "$RUN_DIR"; then
  printf '%s\n' "$RUN_DIR" > {shlex.quote(LOG_ROOT + "/run_dir.txt")}
  rm -rf {shlex.quote(LOG_ROOT + "/run")}
  mkdir -p {shlex.quote(LOG_ROOT + "/run")}
  cp -a "$RUN_DIR"/. {shlex.quote(LOG_ROOT + "/run/")}

  if test -f "$RUN_DIR/comments.json"; then
    cp "$RUN_DIR/comments.json" /workspace/repo/comments.json
    cp "$RUN_DIR/comments.json" {shlex.quote(LOG_ROOT + "/comments.json")}
  fi

  if test -f "$RUN_DIR/result.json"; then
    cp "$RUN_DIR/result.json" {shlex.quote(LOG_ROOT + "/result.json")}
  fi

  if test -f "$RUN_DIR/provenance.json"; then
    cp "$RUN_DIR/provenance.json" {shlex.quote(LOG_ROOT + "/provenance.json")}
  fi
fi

if test -f /workspace/repo/comments.json; then
  cp /workspace/repo/comments.json {shlex.quote(LOG_ROOT + "/scrbench_comments.json")}
fi
""".strip()

        await self._exec(
            environment,
            command,
            timeout_sec=120,
        )