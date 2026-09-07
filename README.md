# AgenticBugHunter

AgenticBugHunter is a secure code review tool.

It reviews code changes in stages: it localizes suspicious changed lines, gathers repository context, retrieves relevant security knowledge, generates CWE hypotheses, validates them, and then produces review comments.

The research benchmark and this tool are related, but they are not exactly the same implementation.

See [research.md](docs/research.md) for more details.

## Install

Requires Python 3.11+ and Git.

Run directly with npm/npx (Node 18+ and Python 3.11+):

```bash
npx agenticbughunter --version
npx agenticbughunter dashboard --repo .
```

Or install the Python CLI directly from GitHub:

```bash
pipx install "git+https://github.com/awsm-research/AgenticBugHunter.git"
```

To reinstall the latest version:

```bash
pipx install --force "git+https://github.com/awsm-research/AgenticBugHunter.git@main"
```

Check that it is installed:

```bash
agenticbughunter --version
```

## Setup

Go inside the Git project you want to review:

```bash
cd your-project
agenticbughunter init --no-hook
```

This creates:

```text
.agenticbughunter.toml
```

The TOML file is the main place to configure the model and pipeline.

Example:

```toml
[llm]
provider = "openai"
base_url = "http://localhost:11435/v1"
model = "qwen3-coder:30b"
api_key = "ollama"
```

The Qwen model is only an example. AgenticBugHunter is not dependent on Qwen and can work with other supported model providers.

Current adapters support:

- OpenAI-compatible Chat Completions APIs
- Anthropic Messages API
- Gemini generateContent API

See [models.md](docs/models.md) for model setup examples.

## Check the setup

Make sure your model/server is already running, then:

```bash
agenticbughunter doctor
agenticbughunter doctor --check-llm
```

## Run a review

Review the latest committed change:

```bash
agenticbughunter review --base HEAD~1 --head HEAD
```

Or compare two branches:

```bash
agenticbughunter review --base main --head feature/login
```

For JSON output:

```bash
agenticbughunter review --base HEAD~1 --head HEAD --json > review.json
```

For a CI-style gate:

```bash
agenticbughunter gate --base HEAD~1 --head HEAD --json > gate.json
```

## Live dashboard

Open the local dashboard while a review is running or to inspect previous runs:

```bash
npx agenticbughunter dashboard --repo .
# or: agenticbughunter dashboard --repo .
```

The dashboard updates every two seconds and displays the active pipeline stage,
stage timings, model and threshold, findings, comments, errors, recent events,
and historical runs. It is read-only and listens on `127.0.0.1:8765` by
default. Use `--port 0` to select an available port or `--no-open` on a remote
machine.

## Model configuration

Normally, configure the model in:

```text
.agenticbughunter.toml
```

Environment variables can also be used when needed, for example in CI or for API keys:

```bash
export ABH_LLM_API_KEY="your-api-key"
```

Environment variables override the TOML configuration.

You can inspect the current configuration with:

```bash
agenticbughunter config show
agenticbughunter config env
```

## Optional Git push hook

By default I recommend starting without the hook:

```bash
agenticbughunter init --no-hook
```

If you want AgenticBugHunter to run automatically before `git push`:

```bash
agenticbughunter install-hook
```

To remove it:

```bash
agenticbughunter uninstall-hook
```

## Pipeline

| Stage | Purpose |
|---|---|
| 1 | Candidate localization |
| 2 | Repository context enrichment |
| 3 | CWE hypothesis generation |
| 4 | Vulnerability validation |
| 5 | Finding filter and review comments |

BM25 retrieval is local and uses bundled security knowledge.


Run outputs are stored in:

```text
.agenticbughunter/runs/
```


## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

AgenticBugHunter is a research-derived review tool. Its findings should support human review, not be treated as proof that a repository is secure.
