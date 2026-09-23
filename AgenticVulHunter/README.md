# AgenticVulHunter

AgenticVulHunter is a four-stage secure code review tool. It reviews your current Git changes and reports security issues that pass the validation threshold.

## Step 1: Install

Install AgenticVulHunter using:

```bash
pipx install agenticvulhunter
```

## Step 2: LLM Setup

You only need:

* Endpoint
* API key
* Model

You can configure them using `avh_setup.toml` or environment variables.

### Option 1: avh_setup.toml

Create `avh_setup.toml` inside the repository you want to review:

```toml
[llm]

endpoint = "http://localhost:11434/v1"
api_key = ""
model = "qwen3-coder:30b"
```

### Option 2: Environment Variables

```bash
export AVH_ENDPOINT="http://localhost:11434/v1"
export AVH_API_KEY="your-key"
export AVH_MODEL="qwen3-coder:30b"
```

Environment variables take priority over `avh_setup.toml`.

## Step 3: Run

Run AgenticVulHunter inside your Git repository:

```bash
agenticvulhunter review
```

The default validation threshold is `0.6`.

To use another threshold:

```bash
agenticvulhunter review 0.7
```
