"""Build the Stage 2.5 CWE-grouped BM25 search index."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage2_5_retriever_core import (
    FILES_DIR,
    PROJECT_DIR,
    build_model,
    resolve_path,
)


def get_extra_rule_paths(
    extra_rules_text: str,
    files_directory: Path,
) -> list[Path]:
    """
    Convert a comma-separated list of rule files into Path objects.

    Example input:
        "python_rules.json,java_rules.json"

    Example output:
        [
            files_directory / "python_rules.json",
            files_directory / "java_rules.json",
        ]
    """

    if not extra_rules_text:
        return []

    rule_paths: list[Path] = []

    # Split the text wherever there is a comma.
    for rule_file in extra_rules_text.split(","):
        rule_file = rule_file.strip()

        # Ignore empty values.
        if not rule_file:
            continue

        path = Path(rule_file).expanduser()

        # If the user gives only a filename, look for it inside files_directory.
        if not path.is_absolute():
            path = files_directory / path

        rule_paths.append(path)

    return rule_paths


def read_command_line_arguments() -> argparse.Namespace:
    """Read the options supplied when this script is run."""

    parser = argparse.ArgumentParser(
        description="Build the Stage 2.5 CWE-grouped BM25 index."
    )

    parser.add_argument(
        "--files-dir",
        default=str(FILES_DIR),
        help="Directory containing sast.json and other Stage 2.5 files.",
    )

    parser.add_argument(
        "--sast",
        default=None,
        help="Path to the main SAST rules JSON file.",
    )

    parser.add_argument(
        "--extra-rules",
        default="",
        help="Comma-separated paths to additional rule files.",
    )

    parser.add_argument(
        "--model-dir",
        default=None,
        help="Directory where the built BM25 model will be saved.",
    )

    return parser.parse_args()


def main() -> None:
    """Prepare the paths, build the model, and print its metadata."""

    args = read_command_line_arguments()

    # Resolve the main files directory.
    files_directory = resolve_path(
        args.files_dir,
        PROJECT_DIR,
    )

    # Use the supplied SAST file, or default to files_dir/sast.json.
    if args.sast:
        sast_path = resolve_path(args.sast, PROJECT_DIR)
    else:
        sast_path = files_directory / "sast.json"

    # Use the supplied model directory, or create it inside files_directory.
    if args.model_dir:
        model_directory = resolve_path(args.model_dir, PROJECT_DIR)
    else:
        model_directory = files_directory / "stage2_5_model"

    # Convert any additional rule filenames into complete paths.
    extra_rule_paths = get_extra_rule_paths(
        args.extra_rules,
        files_directory,
    )

    # Build and save the BM25 retrieval model.
    metadata = build_model(
        sast_path=sast_path,
        model_dir=model_directory,
        extra_rule_paths=extra_rule_paths,
    )

    # Print information about the model that was created.
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()