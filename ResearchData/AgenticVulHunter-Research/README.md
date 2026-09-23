# AgenticVulHunter Research Experiment

SCRBench/Harbor research implementation of AgenticVulHunter.

## Pipeline

```text
Harbor / SCRBench
      ↓
Stage 1: Candidate Selection
      ↓
Stage 2: Knowledge Building
      ↓
Stage 3: CWE Search & Retrieval
      ↓
Stage 4: Validation & Filtering
      ↓
Final secure code review comments
```

## 1. Build the Wheel

Go to the project folder:

```bash
cd ../AgenticVulHunter-Research
```

Install the build package if needed:

```bash
python -m pip install build
```

Build the research package:

```bash
python -m build
```

Check the generated files:

```bash
ls -lh dist/
```

The wheel used by Harbor currently is:

```text
dist/agenticvulhunter_research-0.2.1-py3-none-any.whl
```

---

## 2. Verify Model

Check that the model endpoint is reachable (OpenRouter, GPU hosted, etc.):

```bash
curl http://127.0.0.1:11435/v1/models
```

---

## 3. Control — Full AgenticVulHunter

Run the complete AgenticVulHunter pipeline using Qwen3-Coder-30B:

```bash
ABH_LLM_MODEL=qwen3-coder:30b \
ABH_LLM_BASE_URL=http://host.docker.internal:11435/v1 \
ABH_LLM_API_KEY=ollama \
ABH_PIPELINE_SKIP_STAGE2=false \
caffeinate -i python run_avh_research_harbor.py \
  --n-tasks 0 \
  --run-timeout-sec 43200 \
  --job-name avh-control-r1 \
  --jobs-dir jobs
```

`--n-tasks 0` runs all SCRBench tasks.

---

## 4. Model Comparison

Keep the complete pipeline unchanged and only change the model.

Example using Devstral 24B:

```bash
ABH_LLM_MODEL=devstral:24b \
ABH_LLM_BASE_URL=http://host.docker.internal:11435/v1 \
ABH_LLM_API_KEY=ollama \
ABH_PIPELINE_SKIP_STAGE2=false \
caffeinate -i python run_avh_research_harbor.py \
  --n-tasks 0 \
  --run-timeout-sec 43200 \
  --job-name avh-control-devstral24b-r1 \
  --jobs-dir jobs
```

Jobs will be created under:

```text
jobs/
```

---

## Project Structure

```text
AgenticVulHunter-Research/
│
├── README.md
├── pyproject.toml
├── run_avh_research_harbor.py
├── .gitignore
│
├── avh_harbor/
│   ├── __init__.py
│   ├── agent.py
│   └── preflight.py
│
├── scrbench/
│   └── ...
│
├── src/
│   └── agenticbughunter/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── diff.py
│       ├── git.py
│       ├── models.py
│       ├── pipeline.py
│       ├── research_diff.py
│       ├── resources.py
│       ├── runlog.py
│       │
│       ├── stages/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── stage1_candidates.py
│       │   ├── stage2_context.py
│       │   ├── stage3_hypotheses.py
│       │   ├── stage4_judge.py
│       │   ├── stage5_filter.py
│       │   └── scoring.py
│       │
│       ├── llm/
│       │   ├── __init__.py
│       │   ├── agent.py
│       │   ├── client.py
│       │   ├── protocol.py
│       │   ├── providers.py
│       │   ├── tools.py
│       │   └── types.py
│       │
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── bm25.py
│       │   └── repo.py
│       │
│       ├── bm25/
│       │   ├── __init__.py
│       │   ├── stage2_5_retriever_core.py
│       │   └── files/
│       │       └── stage2_5_model/
│       │
│       ├── prompts/
│       │   ├── stage1_candidates_research.md
│       │   ├── stage2_context.md
│       │   ├── stage3_hypotheses.md
│       │   ├── stage3_hypotheses_no_bm25.md
│       │   └── stage4_judge.md
│       │
│       └── research_data/
│           ├── experiment.toml
│           └── stage_1_annotated/
│               ├── annotated/
│               │   └── 144 .diff files
│               └── raw/
│                   └── 144 .diff files
│
└── dist/
    ├── agenticvulhunter_research-0.2.1-py3-none-any.whl
    └── agenticvulhunter_research-0.2.1.tar.gz
```

### Main Folders

- `avh_harbor/` contains the Harbor wrapper used to run AgenticVulHunter on SCRBench.
- `src/agenticbughunter/` contains the main AgenticVulHunter implementation.
- `stages/` contains the pipeline stage implementations.
- `llm/` contains the language model connection and agent logic.
- `bm25/` contains the BM25-based CWE retriever.
- `prompts/` contains the prompts used by the pipeline.
- `research_data/` contains the frozen SCRBench diff artifacts.
- `dist/` contains the built Python package used by Harbor.
