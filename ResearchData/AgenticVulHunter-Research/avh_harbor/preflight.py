"""Checks that Harbor has prepared the SCRBench repository correctly."""

import json
import re
from typing import Any

from .common import LOG_ROOT


# SCRBench diff IDs are 40-character commit hashes
HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")


def preflight_script(
    repo_path: str = "/workspace/repo",
    setup_script_path: str = "/workspace/setup_repo.sh",
    log_root_path: str = LOG_ROOT,
    readiness_timeout_sec: int = 0,
) -> str:
    """Create the readiness check that runs inside the task container."""

    return f"""
import json
import pathlib
import re
import time

repo = pathlib.Path({repo_path!r})
setup_script = pathlib.Path({setup_script_path!r})
log_root = pathlib.Path({log_root_path!r})
log_root.mkdir(parents=True, exist_ok=True)

# Store the current readiness status
result = {{
    "repo_exists": False,
    "setup_script_exists": setup_script.exists(),
    "diff_id": None,
    "change_input": "frozen_precomputed_A_D_C_annotations",
    "repository_mode": "current_working_tree_knowledge_base",
    "status": "error",
    "failed_checks": [],
    "setup_script_diagnostic": None,
    "readiness_attempts": 0,
    "readiness_timeout_sec": {int(readiness_timeout_sec)},
}}

deadline = time.monotonic() + max(0, result["readiness_timeout_sec"])

# Keep checking until the repository is ready or the timeout is reached
while True:
    result["readiness_attempts"] += 1
    result["repo_exists"] = repo.is_dir()
    result["setup_script_exists"] = setup_script.exists()
    result["diff_id"] = None
    result["setup_script_diagnostic"] = None

    # Read the SCRBench commit hash from setup_repo.sh
    if result["setup_script_exists"]:
        try:
            text = setup_script.read_text(encoding="utf-8", errors="ignore")

            match = re.search(
                r"(?m)^\\s*COMMIT_HASH\\s*=\\s*[\\x22\\x27]?([0-9a-fA-F]{{40}})",
                text,
            )

            if match:
                result["diff_id"] = match.group(1).lower()
            else:
                result["setup_script_diagnostic"] = "COMMIT_HASH not found"

        except OSError as exc:
            result["setup_script_diagnostic"] = (
                f"{{type(exc).__name__}}: {{exc}}"
            )

    # Check that all required SCRBench inputs are available
    checks = (
        ("repo_exists", result["repo_exists"]),
        ("setup_script_exists", result["setup_script_exists"]),
        ("diff_id", result["diff_id"] is not None),
    )

    result["failed_checks"] = [
        name for name, passed in checks if not passed
    ]

    if not result["failed_checks"]:
        result["status"] = "ok"
        break

    if time.monotonic() >= deadline:
        break

    time.sleep(1)

# Save the preflight result for debugging
payload = json.dumps(result, indent=2, sort_keys=True) + "\\n"

(log_root / "preflight.json").write_text(
    payload,
    encoding="utf-8",
)

print(payload, end="")
""".strip()


def parse_preflight(output: str) -> dict[str, Any]:
    """Check that the preflight result is valid."""

    try:
        result = json.loads(output)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Prepared-diff preflight produced invalid JSON: {exc}"
        ) from exc

    # The preflight output should always be a JSON object
    if not isinstance(result, dict):
        raise RuntimeError(  # noqa: TRY004 - container protocol failure
            "Prepared-diff preflight produced a non-object result"
        )

    # Stop if the SCRBench environment is not ready
    if result.get("status") != "ok":
        failed = result.get("failed_checks")

        detail = (
            ", ".join(map(str, failed))
            if isinstance(failed, list)
            else "unknown"
        )

        raise RuntimeError(
            "SCRBench infrastructure/preflight error: prepared-diff inputs are "
            f"not ready; failed checks: {detail}. "
            f"See {LOG_ROOT}/preflight.json. setup_repo.sh was not re-run."
        )

    diff_id = result.get("diff_id")

    # Make sure the extracted diff ID is a valid commit hash
    if not isinstance(diff_id, str) or not HEX40.fullmatch(diff_id):
        raise RuntimeError(
            "Prepared-diff preflight returned an invalid SCRBench diff_id"
        )

    return result