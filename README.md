# AgenticBugHunter

A research-derived secure code review tool: localize changed lines, gather
repository evidence, retrieve security knowledge, form CWE hypotheses, and
judge the evidence before producing review comments.

This is the application built from the staged research workflow. The benchmark
harness and the application are related implementations, not interchangeable
experiments. [Research mapping and differences](docs/research.md).

## Quick start

Requires Python 3.11+ and Git. Install this downloaded source release:
c
Inside the Git repository you want to review:

```bash
# Initial setup without changing your push workflow.
agenticbughunter init --no-hook

# Point the tool at your chosen OpenAI-compatible text model.
export ABH_LLM_PROVIDER="openai"
export ABH_LLM_BASE_URL="http://localhost:11435/v1"
export ABH_LLM_MODEL="qwen3-coder:30b"
export ABH_LLM_API_KEY="ollama"

agenticbughunter doctor
agenticbughunter doctor --check-llm
agenticbughunter review --base HEAD~1 --head HEAD
```

The model/server must already be running. The compatibility check makes a small
model request, which may incur API cost; it sends no repository contents.
The Qwen model above is an example and remains the backward-compatible default,
not a required model. Model quality and context capacity still matter.

## Switch models through `export`

Choose a backend, endpoint, model ID, and key. No Qwen CLI, native function
calling, MCP server, or vendor SDK is required by the application.

| Provider setting | Endpoint shape | Supported transport |
|---|---|---|
| `openai` | `https://YOUR-ENDPOINT/v1` | Chat Completions-compatible text API |
| `anthropic` | `https://api.anthropic.com/v1` | Anthropic Messages API |
| `gemini` | `https://generativelanguage.googleapis.com/v1beta` | Gemini generateContent API |

Use a model ID enabled by your provider. See [model setup](docs/models.md) for
copyable exports, reasoning-model options, and custom Python backends. Native
Responses API, Bedrock, Vertex authentication, and Azure-specific routing are
not implemented by these adapters; use a compatible gateway or custom backend.

## How the research becomes a tool

| Stage | Responsibility | What the model does | What Python enforces |
|---|---|---|---|
| 1. Candidate localization | Anchor review to the diff | Select suspicious changed lines | Actual diff locations, canonical statement, deduplication, limits |
| 2. Context enrichment | Establish repository evidence | Read bounded context and resolve relevant symbols | Read-only operations and immutable candidate identity |
| 3. CWE hypotheses | Match evidence to security knowledge | Interpret/refine BM25 searches | Initial retrieval, search budget, retrieved CWE membership |
| 4. Judge | Assess each candidate–CWE pair | Score five evidence categories | Immutable identity, numeric scores, application score caps |
| 5. Filter | Produce comments | No model call | Threshold, verdict, comment requirement, sorting, output limit |

BM25 retrieves bundled security rules **locally**. It is security-knowledge
retrieval, not execution of a SAST scanner. There is no separate retrieval server.

## Everyday use

```bash
# Inspect a committed change; this does not review unstaged or staged edits.
agenticbughunter review --base main --head feature/login

# Machine-readable report. A successful review returns 0 even with findings.
agenticbughunter review --base HEAD~1 --head HEAD --json > review.json

# CI gate: 0 = pass, 1 = findings block, 2 = execution/configuration error.
agenticbughunter gate --base HEAD~1 --head HEAD --json > gate.json

agenticbughunter show-run
agenticbughunter config show
agenticbughunter config env
```

Review uses a detached worktree by default, so evidence comes from the selected
commit. Diff semantics are Git's `base...head` (merge-base to head). The actual
merge-base revision is used for old-line evidence; see
[operations](docs/operations.md).

Run artifacts live under `.agenticbughunter/runs/<run-id>/`. They contain the
resolved commits, effective configuration, prompt hashes, inputs, model text,
retrieval results, judgments, and final comments. API-key fields are redacted;
repository text and model-generated text are not a general secret scrubber.

## Optional push gate

Start with manual review to understand the findings on your repositories. To
opt into a managed pre-push gate:

```bash
agenticbughunter install-hook
agenticbughunter uninstall-hook
```

`init` without `--no-hook` also installs the hook. The underlying research can
identify weaknesses that a patch **fixes** as well as weaknesses it introduces;
a supported comment is not automatically a new regression. Consider this
before using findings to block pushes. Review is an aid to human assessment,
not proof that a commit is secure.

## Read or extend the code

- [Architecture and module map](docs/architecture.md): where each responsibility lives.
- [Models and provider adapters](docs/models.md): exports, compatibility, extension interface.
- [Configuration reference](docs/configuration.md): every setting and precedence.
- [Research mapping](docs/research.md): method, preserved policy, and benchmark differences.
- [Operations and troubleshooting](docs/operations.md): outputs, budgets, hooks, errors.
- [Development and validation](docs/development.md): tests and release boundaries.
- [Release validation](VALIDATION.md): what was actually tested.
- [Change log](CHANGELOG.md): engineering changes versus analysis changes.

```bash
# Offline tests: real Git and local BM25, scripted model outputs.
PYTHONPATH=src python -m unittest discover -s tests -v
```

Adapters are covered by offline request/response tests. This release has not
been validated against live paid models or rerun on the full research benchmark;
its test results do not establish vulnerability precision or recall.
