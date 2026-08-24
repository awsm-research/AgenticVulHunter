"""FastAPI server for the recovered Stage 2.5 rule-BM25 CWE retriever."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from stage2_5_retriever_core import (
    DEFAULT_MODEL_DIR,
    DEFAULT_SAST_PATH,
    FILES_DIR,
    PROJECT_DIR,
    item_language,
    load_or_build_model,
    resolve_path,
)


class PredictRequest(BaseModel):
    items: list[dict[str, Any]]
    top_k: int = 10
    min_raw_score: float | None = None


def parse_extra_rules(value: str | None, files_dir: Path) -> list[Path] | None:
    if value is None:
        return None
    if value == "":
        return []

    paths: list[Path] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        path = Path(part).expanduser()
        if not path.is_absolute():
            path = files_dir / path
        paths.append(path)
    return paths


def create_app(
    model_dir: Path = DEFAULT_MODEL_DIR,
    sast_path: Path = DEFAULT_SAST_PATH,
    extra_rule_paths: list[Path] | None = None,
    rebuild: bool = False,
) -> FastAPI:
    retriever = load_or_build_model(
        model_dir=model_dir,
        sast_path=sast_path,
        extra_rule_paths=extra_rule_paths,
        rebuild=rebuild,
    )

    app = FastAPI(title="Stage 2.5 Rule-BM25 CWE Retriever")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "algorithm": retriever.metadata.get("algorithm"),
            "rules": len(retriever.rules),
            "cwes": retriever.metadata.get("cwe_count"),
            "model_dir": str(retriever.model_dir),
        }

    @app.post("/predict")
    def predict(request: PredictRequest) -> dict[str, Any]:
        predictions = []

        for item in request.items:
            rules = retriever.rank(
                item,
                top_k=max(1, request.top_k),
                min_raw_score=request.min_raw_score,
            )

            predictions.append(
                {
                    **item,
                    "language": item_language(item),
                    "retrieval_skipped": False,
                    "retrieval_skip_reason": None,
                    "top_sast_rules": rules,
                }
            )

        return {"predictions": predictions}

    return app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the recovered Stage 2.5 rule-BM25 CWE retriever server."
    )
    parser.add_argument("--files-dir", default=str(FILES_DIR))
    parser.add_argument("--model-dir", default=None)
    parser.add_argument("--sast", default=None)
    parser.add_argument("--extra-rules", default=None)
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5056)
    args = parser.parse_args()

    files_dir = resolve_path(args.files_dir, PROJECT_DIR)
    model_dir = (
        resolve_path(args.model_dir, PROJECT_DIR)
        if args.model_dir
        else files_dir / "stage2_5_model"
    )
    sast_path = (
        resolve_path(args.sast, PROJECT_DIR)
        if args.sast
        else files_dir / "sast.json"
    )
    extra_rule_paths = parse_extra_rules(args.extra_rules, files_dir)

    app = create_app(
        model_dir=model_dir,
        sast_path=sast_path,
        extra_rule_paths=extra_rule_paths,
        rebuild=args.rebuild,
    )

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()