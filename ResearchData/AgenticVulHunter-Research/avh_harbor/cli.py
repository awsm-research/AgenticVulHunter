"""Command-line launcher for AgenticVulHunter Harbor jobs."""

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

from .common import AGENT_SPEC, PROJECT_DIR


# Default SCRBench dataset and frozen research wheel
DEFAULT_DATASET = PROJECT_DIR / "scrbench"
DEFAULT_WHEEL = PROJECT_DIR / "dist/agenticvulhunter_research-0.2.1-py3-none-any.whl"


def harbor_help(harbor: str) -> str:
    """Get the available options from the Harbor CLI."""

    result = subprocess.run(
        [harbor, "run", "--help"],
        text=True,
        capture_output=True,
        check=False,
    )

    return (result.stdout or "") + "\n" + (result.stderr or "")


def build_harbor_command(
    args: argparse.Namespace,
    help_text: str,
) -> list[str]:
    """Build the Harbor command used to run the experiment."""

    dataset = Path(args.dataset).expanduser().resolve()
    wheel = Path(args.wheel).expanduser().resolve()

    # Check that the required files exist
    if not dataset.is_dir():
        raise FileNotFoundError(
            f"SCRBench dataset directory not found: {dataset}"
        )

    if not wheel.is_file():
        raise FileNotFoundError(
            f"Research wheel not found: {wheel}"
        )

    # Start the Harbor command with the SCRBench dataset
    command = [
        args.harbor,
        "run",
        "-p",
        str(dataset),
    ]

    # Harbor versions may use different agent options
    if "--agent-import-path" in help_text:
        command += [
            "--agent-import-path",
            AGENT_SPEC,
        ]
    else:
        command += [
            "--agent",
            AGENT_SPEC,
        ]

    # Model name used by Harbor for the experiment
    if "--model" in help_text or " -m" in help_text:
        command += [
            "--model",
            args.model,
        ]

    # Pass configuration values to the research agent
    command += [
        "--ak",
        f"wheel_path={wheel}",
    ]

    command += [
        "--ak",
        f"run_timeout_sec={int(args.run_timeout_sec)}",
    ]

    # Number of tasks that can run at the same time
    if "--n-concurrent" in help_text:
        command += [
            "--n-concurrent",
            str(args.n_concurrent),
        ]

    # Optional Harbor timeout adjustment
    if (
        args.agent_timeout_multiplier is not None
        and "--agent-timeout-multiplier" in help_text
    ):
        command += [
            "--agent-timeout-multiplier",
            str(args.agent_timeout_multiplier),
        ]

    # Limit the number of SCRBench tasks
    if args.n_tasks > 0 and "--n-tasks" in help_text:
        command += [
            "--n-tasks",
            str(args.n_tasks),
        ]

    # Optional job name
    if args.job_name and "--job-name" in help_text:
        command += [
            "--job-name",
            args.job_name,
        ]

    # Optional location for Harbor job outputs
    if args.jobs_dir and "--jobs-dir" in help_text:
        jobs_dir = Path(args.jobs_dir).expanduser().resolve()

        command += [
            "--jobs-dir",
            str(jobs_dir),
        ]

    # Keep containers after the experiment if requested
    if args.keep_containers and "--no-delete" in help_text:
        command += [
            "--no-delete",
        ]

    # Automatically confirm Harbor execution
    if "--yes" in help_text:
        command += [
            "--yes",
        ]

    return command


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line arguments for the launcher."""

    parser = argparse.ArgumentParser(
        description=(
            "Run AgenticVulHunter Research on unchanged "
            "SCRBench tasks through Harbor"
        )
    )

    parser.add_argument(
        "--dataset",
        default=str(DEFAULT_DATASET),
        help="SCRBench task directory",
    )

    parser.add_argument(
        "--wheel",
        default=str(DEFAULT_WHEEL),
        help="frozen research wheel",
    )

    parser.add_argument(
        "--harbor",
        default="harbor",
        help="Harbor CLI path",
    )

    parser.add_argument(
        "--model",
        default="qwen3-coder:30b",
        help="Harbor bookkeeping model name",
    )

    parser.add_argument(
        "--n-tasks",
        type=int,
        default=1,
        help="0 = all tasks",
    )

    parser.add_argument(
        "--n-concurrent",
        type=int,
        default=1,
    )

    parser.add_argument(
        "--run-timeout-sec",
        type=int,
        default=7200,
    )

    parser.add_argument(
        "--agent-timeout-multiplier",
        type=float,
        default=None,
        help="multiply Harbor's outer agent timeout",
    )

    parser.add_argument(
        "--job-name",
        default="avh-research",
    )

    parser.add_argument(
        "--jobs-dir",
        default=None,
    )

    parser.add_argument(
        "--keep-containers",
        action="store_true",
    )

    parser.add_argument(
        "--skip-stage2",
        action="store_true",
        help=(
            "run the Stage-2 ablation using the "
            "otherwise frozen configuration"
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the Harbor experiment using the selected options."""

    # Read command-line arguments
    args = build_parser().parse_args(argv)

    # Check which options are supported by the installed Harbor version
    help_text = harbor_help(args.harbor)

    if not help_text.strip():
        print(
            f"Could not execute `{args.harbor} run --help`.",
            file=sys.stderr,
        )
        return 2

    try:
        command = build_harbor_command(
            args,
            help_text,
        )
    except Exception as exc:  # noqa: BLE001 - preserve launcher behaviour
        print(
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2

    # Show the full Harbor command before running it
    print(shlex.join(command))

    # Dry run only prints the command
    if args.dry_run:
        return 0

    env = dict(os.environ)

    # Enable the Stage-2 ablation when requested
    if args.skip_stage2:
        env["ABH_PIPELINE_SKIP_STAGE2"] = "true"

    # Make the project package available to Harbor
    previous = env.get("PYTHONPATH", "")

    env["PYTHONPATH"] = (
        str(PROJECT_DIR)
        + (os.pathsep + previous if previous else "")
    )

    # Start the Harbor experiment
    process = subprocess.run(
        command,
        env=env,
        check=False,
    )

    return int(process.returncode)