# AgenticVulHunter

AgenticVulHunter is a four-stage agentic secure code review tool. It reviews the
current Git change and returns comments that pass the Stage 4 validation
threshold.

## Pipeline

```text
Git diff
   ↓
Stage 1: Candidate localisation
   ↓
Stage 2: Context enrichment
   ↓
Stage 3: CWE hypothesis generation
   ↓
Stage 4: Vulnerability validation
   ↓
Review comments above the threshold
```

The pipeline runs directly on the repository. It does not use annotated
SCRBench data at runtime.

## Install

From this folder:

```bash
pipx install . --force
```

Check the installed version:

```bash
agenticvulhunter --version
```

## LLM setup

The endpoint, API key, and model are the only public LLM setup values. Other
research settings stay inside AgenticVulHunter.

### Option 1: `avh_setup.toml`

Create `avh_setup.toml` in the repository where the review is run:

```toml
[llm]
endpoint = "http://localhost:11434/v1"
api_key = ""
model = "qwen3-coder:30b"
```

For an API endpoint that requires a key:

```toml
[llm]
endpoint = "https://example.com/v1"
api_key = "your-key"
model = "your-model"
```

### Option 2: exports

```bash
export AVH_ENDPOINT="http://localhost:11434/v1"
export AVH_API_KEY="your-key"
export AVH_MODEL="qwen3-coder:30b"
```

Exports take priority over `avh_setup.toml` when both are present.

Do not commit a real API key to Git.

## Run a review

Use the default threshold of `0.6`:

```bash
agenticvulhunter review
```

Use another threshold:

```bash
agenticvulhunter review 0.7
```

The terminal shows the AVH banner and the status of all four stages while the
review is running.

## Threshold

The threshold is applied to the final Stage 4 validation score. It is not a
separate pipeline stage.

```text
agenticvulhunter review       -> 0.6
agenticvulhunter review 0.7   -> 0.7
agenticvulhunter review 0.9   -> 0.9
```

## JSON output

```bash
agenticvulhunter review --json
```


