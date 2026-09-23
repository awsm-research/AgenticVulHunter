"""Minimal Qwen baseline for reproducing the AgenticSCR detector -> validator flow."""

import base64
import json
import os
import re
import shlex
from pathlib import Path
from typing import Any, ClassVar

from harbor.agents.installed.base import EnvVar, with_prompt_template
from harbor.agents.installed.qwen_code import QwenCode
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext


class AgenticSCRQwenBaseline(QwenCode):
    """Run the AgenticSCR-style detector and validator with Qwen Code."""

    SUPPORTS_ATIF: bool = True

    ENV_VARS: ClassVar[list[EnvVar]] = [
        EnvVar(
            "api_key",
            env="OPENAI_API_KEY",
            type="str",
            env_fallback="OPENAI_API_KEY",
        ),
        EnvVar(
            "base_url",
            env="OPENAI_BASE_URL",
            type="str",
            env_fallback="OPENAI_BASE_URL",
        ),
        EnvVar(
            "stage_timeout_sec",
            env="BASELINE_STAGE_TIMEOUT_SEC",
            type="int",
            default=3600,
            env_fallback="BASELINE_STAGE_TIMEOUT_SEC",
        ),
    ]

    @staticmethod
    def name() -> str:
        return "agenticscr-qwen-baseline"

    @property
    def agent_root(self) -> Path:
        return Path(__file__).resolve().parent

    def _read_prompt(self, filename: str) -> str:
        path = self.agent_root / "baseline_prompts" / filename
        if not path.is_file():
            raise FileNotFoundError(f"Missing baseline prompt: {path}")
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            raise ValueError(f"Baseline prompt is empty: {path}")
        return text

    def _agenticscr_prompts(self) -> tuple[str, str]:
        """Load the paper prompts, changing only Harbor-specific file paths."""
        detector = self._read_prompt("detector-subagent_original.md").replace(
            "`sast.json` file in the repository",
            "`/workspace/repo/memory/sast.json` file",
        )
        validator = self._read_prompt("validator-subagent_original.md")
        validator = validator.replace(
            "<target_warning_path>",
            "/workspace/repo/detection_temp.json",
        ).replace(
            "`cwe.json` file in the repository",
            "`/workspace/repo/memory/cwe.json` file",
        )
        return detector, validator

    def _qwen_env(self) -> dict[str, str]:
        env = {**self._resolved_env_vars}
        model_name = getattr(self, "model_name", None)
        if model_name:
            env["OPENAI_MODEL"] = model_name
        elif "OPENAI_MODEL" in os.environ:
            env["OPENAI_MODEL"] = os.environ["OPENAI_MODEL"]
        else:
            env["OPENAI_MODEL"] = "qwen/qwen3-coder"
        return env

    def _parse_jsonl(self) -> list[dict[str, Any]]:
        """Merge the detector and validator Qwen sessions chronologically."""
        sessions_dir = self.logs_dir / "qwen-sessions"
        if not sessions_dir.is_dir():
            return []

        events: list[dict[str, Any]] = []
        session_files = sorted(
            sessions_dir.rglob("*.jsonl"),
            key=lambda path: path.stat().st_mtime,
        )
        for path in session_files:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    events.append(event)
        return events

    async def _copy_file_to_container(
        self,
        environment: BaseEnvironment,
        source: Path,
        destination: str,
    ) -> None:
        """Copy one local baseline resource into the Harbor task container."""
        if not source.is_file():
            raise FileNotFoundError(f"Missing baseline resource: {source}")

        encoded = base64.b64encode(source.read_bytes()).decode("ascii")
        parent = str(Path(destination).parent)
        tmp_path = f"/tmp/{source.name}.b64"

        await environment.exec(
            command=(
                "mkdir -p " + shlex.quote(parent) + " && : > " + shlex.quote(tmp_path)
            ),
            cwd="/workspace/repo",
        )

        # Keep command size small enough for the container shell.
        for start in range(0, len(encoded), 30000):
            chunk = encoded[start : start + 30000]
            script = (
                f"cat >> {shlex.quote(tmp_path)} <<'EOF_BASELINE_B64'\n"
                f"{chunk}\n"
                "EOF_BASELINE_B64"
            )
            await environment.exec(
                command=f"sh -c {shlex.quote(script)}",
                cwd="/workspace/repo",
            )

        script = (
            "set -e\n"
            f"base64 -d {shlex.quote(tmp_path)} > {shlex.quote(destination)}\n"
            f"rm -f {shlex.quote(tmp_path)}\n"
            f"test -s {shlex.quote(destination)}"
        )
        await environment.exec(
            command=f"sh -c {shlex.quote(script)}",
            cwd="/workspace/repo",
        )

    async def _prepare_memory(self, environment: BaseEnvironment) -> None:
        """Place only the three AgenticSCR memory resources in the task container."""
        memory_root = self.agent_root / "baseline_memory"
        for filename in ("sast.json", "cwe.json", "scr.json"):
            await self._copy_file_to_container(
                environment,
                memory_root / filename,
                f"/workspace/repo/memory/{filename}",
            )

        # Verify that the copied resources are valid JSON before running Qwen.
        await environment.exec(
            command=(
                "python3 -m json.tool memory/sast.json >/dev/null && "
                "python3 -m json.tool memory/cwe.json >/dev/null && "
                "python3 -m json.tool memory/scr.json >/dev/null"
            ),
            cwd="/workspace/repo",
        )

    def _final_output_path(self, instruction: str) -> str:
        """Use the JSON output requested by Harbor, otherwise comments.json."""
        paths = re.findall(
            r"/workspace/repo/[A-Za-z0-9_.\-/]+\.json",
            instruction,
        )
        for path in paths:
            if "comment" in path.lower() or "output" in path.lower():
                return path.replace("/workspace/repo/", "")
        return "comments.json"

    async def _run_qwen_phase(
        self,
        environment: BaseEnvironment,
        prompt: str,
        log_name: str,
        env: dict[str, str],
    ) -> None:
        """Run one Qwen Code phase inside the task repository."""
        timeout_sec = int(
            self._resolved_env_vars.get("BASELINE_STAGE_TIMEOUT_SEC", "3600")
        )
        command = (
            ". ~/.nvm/nvm.sh 2>/dev/null || true; "
            "cd /workspace/repo; "
            "mkdir -p /logs/agent; "
            f"timeout {timeout_sec}s qwen --yolo --prompt={shlex.quote(prompt)} "
            f"2>&1 | tee /logs/agent/{shlex.quote(log_name)}; "
            "status=${PIPESTATUS[0]}; "
            "echo '[QWEN EXIT] status='\"$status\"; "
            'exit "$status"'
        )

        await self.exec_as_agent(
            environment,
            command=command,
            env=env,
            timeout_sec=timeout_sec + 30,
        )

        # Preserve Qwen sessions so Harbor/QwenCode can build its trajectory.
        await self.exec_as_agent(
            environment,
            command=(
                "mkdir -p /logs/agent/qwen-sessions; "
                "cp -r ~/.qwen/projects/. /logs/agent/qwen-sessions/ 2>/dev/null || true"
            ),
            env=env,
            timeout_sec=30,
        )

    async def _ensure_json_array(
        self,
        environment: BaseEnvironment,
        path: str,
    ) -> None:
        """Require baseline output to be a JSON array."""
        script = f"""
from pathlib import Path
import json

p = Path('/workspace/repo') / {path!r}
if not p.is_file():
    raise FileNotFoundError(f'baseline output was not created: {{p}}')

text = p.read_text(encoding='utf-8', errors='strict').strip()
if not text:
    raise ValueError(f'baseline output is empty: {{p}}')

value = json.loads(text)
if not isinstance(value, list):
    raise ValueError(f'baseline output is not a JSON array: {{p}}')
"""
        result = await environment.exec(
            command=f"python3 -c {shlex.quote(script)}",
            cwd="/workspace/repo",
        )
        if result.return_code != 0:
            output = (result.stdout or result.stderr or "").strip()
            raise RuntimeError(output or f"Invalid baseline output: {path}")

    async def _materialize_json_array(
        self,
        environment: BaseEnvironment,
        *,
        log_name: str,
        output_path: str,
    ) -> None:
        """Write a JSON array returned in Qwen's response to Harbor's output file."""
        script = f"""
from pathlib import Path
import json

target = Path("/workspace/repo") / {output_path!r}
if target.is_file():
    try:
        existing = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        existing = None
    if isinstance(existing, list):
        raise SystemExit(0)

log = Path("/logs/agent") / {log_name!r}
text = log.read_text(encoding="utf-8", errors="replace")
decoder = json.JSONDecoder()
arrays = []
for index, character in enumerate(text):
    if character != "[":
        continue
    try:
        value, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(value, list):
        arrays.append(value)

if not arrays:
    raise ValueError(f"Qwen did not return a JSON array in {{log}}")

target.write_text(json.dumps(arrays[-1], ensure_ascii=False, indent=2) + "\\n")
"""
        result = await environment.exec(
            command=f"python3 -c {shlex.quote(script)}",
            cwd="/workspace/repo",
        )
        if result.return_code != 0:
            output = (result.stdout or result.stderr or "").strip()
            raise RuntimeError(
                output or f"Unable to create baseline output: {output_path}"
            )

    @with_prompt_template
    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        env = self._qwen_env()
        await self._prepare_memory(environment)

        detector_output = "detection_temp.json"
        final_output = self._final_output_path(instruction)

        await environment.exec(
            command=f"rm -f {shlex.quote(detector_output)} {shlex.quote(final_output)}",
            cwd="/workspace/repo",
        )

        detector_prompt, validator_prompt = self._agenticscr_prompts()

        # The baseline prompts already define the AgenticSCR workflow and paths.
        detector_prompt += """

Run this detector directly in the current Qwen session. Do not delegate to another agent.
Write the detector findings to /workspace/repo/detection_temp.json.
""".strip()

        validator_prompt += f"""

Run this validator directly in the current Qwen session. Do not delegate to another agent.
Only validate findings already present in /workspace/repo/detection_temp.json.
Write the final findings to /workspace/repo/{final_output}.
""".strip()

        (self.logs_dir / "prompt_detector.txt").write_text(
            detector_prompt,
            encoding="utf-8",
        )
        (self.logs_dir / "prompt_validator.txt").write_text(
            validator_prompt,
            encoding="utf-8",
        )

        await self._run_qwen_phase(
            environment,
            detector_prompt,
            "agenticscr-detector.txt",
            env,
        )
        await self._materialize_json_array(
            environment,
            log_name="agenticscr-detector.txt",
            output_path=detector_output,
        )
        await self._ensure_json_array(environment, detector_output)

        await self._run_qwen_phase(
            environment,
            validator_prompt,
            "agenticscr-validator.txt",
            env,
        )
        await self._materialize_json_array(
            environment,
            log_name="agenticscr-validator.txt",
            output_path=final_output,
        )
        await self._ensure_json_array(environment, final_output)
