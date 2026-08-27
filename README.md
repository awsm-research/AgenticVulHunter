# AgenticBugHunter

AgenticBugHunter is a project-local, staged secure-code-review Git gate.

## Pipeline

1. **Stage 1 : Candidate localisation**  
   Identifies suspicious added or deleted diff lines.

2. **Stage 2 : Context enrichment**  
   Explores relevant repository context for each candidate.

3. **Stage 3 : CWE hypothesis generation**  
   Uses the bundled BM25/SAST retriever to retrieve and reason over CWE candidates.

4. **Stage 4 : Validation**  
   Validates each candidate and CWE hypothesis.

5. **Stage 5 : Filtering**  
   Applies the confidence threshold and produces supported findings.

BM25 runs locally inside AgenticBugHunter. No separate BM25 server or endpoint is required.

## Install

Install AgenticBugHunter directly from GitHub:

```bash
pipx install "git+https://github.com/awsm-research/AgenticBugHunter.git"
```

For development:

```bash
python -m pip install -e .
```

## Initialize

```bash
agenticbughunter init
agenticbughunter doctor
```

This creates `.agenticbughunter.toml`, runtime logs, and a managed pre-push hook.

## Configuration
`agenticbughunter init` creates a readable project-level `.agenticbughunter.toml` with all settings. These can be overirded using CLI

```bash
# Inspect the effective configuration
agenticbughunter config show

# Read one value
agenticbughunter config get pipeline.confidence_threshold

# Change one value without hand-editing TOML
agenticbughunter config set pipeline.confidence_threshold 0.80
agenticbughunter config set pipeline.max_candidates 3
```

TOML is the normal project configuration, as the setting remain saved in file, until the file is deleted or overridden. 

- An environment variable set using export remain active for the current terminal session,
export ABH_PIPELINE_MAX_CANDIDATES=3 
agenticbughunter review --base HEAD~1 --head HEAD

- A environment variable added before a command applies to that command only.
ABH_PIPELINE_MAX_CANDIDATES=3 agenticbughunter review --base HEAD~1 --head HEAD

```

Temporary field overrides still:

```bash
ABH_PIPELINE_MAX_CANDIDATES=3 \
ABH_PIPELINE_CONFIDENCE_THRESHOLD=0.80 \
ABH_BM25_TOP_K=6 \
agenticbughunter review
```

Run `agenticbughunter config env` to see the complete mapping. The existing `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `OPENAI_MODEL` variables remain supported for compatibility.

### UI settings

The terminal presentation is controlled separately from the review algorithm:

```toml
[ui]
banner = true
live_progress = true
show_config = true
show_stage_details = true
```

## Run

Review the latest commit:

```bash
agenticbughunter review
```

Review specific revisions:

```bash
# Review the latest commit
agenticbughunter review --base HEAD~1 --head HEAD

# Review the last 3 commits
agenticbughunter review --base HEAD~3 --head HEAD

# Review a feature branch against main
agenticbughunter review --base main --head feature/login
```

```text
.agenticbughunter/runs/<run-id>/
```

### Terminal experience

```text
 █████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██║  ██║
███████║██████╔╝███████║
██╔══██║██╔══██╗██╔══██║
██║  ██║██████╔╝██║  ██║
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝
AGENTIC BUG HUNTER  v0.5.0
Staged secure code review

╭─ Secure review ─────────────────────────────────────────────────╮
│ Repository  /path/to/project                                   │
│ Review      main → HEAD                                        │
│ Model       qwen3-coder:30b                                    │
│ TOML        /path/to/project/.agenticbughunter.toml             │
│ Policy      threshold 0.75 · candidates 5 · BM25 top-k 10      │
╰─────────────────────────────────────────────────────────────────╯

╭ Pipeline ───────────────────────────────────────────────────────╮
│ ✓ 1/5  Candidate localisation                  8.4s · 3 candidates│
│ ◐ 2/5  Context enrichment                              running │
│ ○ 3/5  CWE hypothesis generation                       pending │
│ ○ 4/5  Vulnerability validation                        pending │
│ ○ 5/5  Finding filter & review comments                pending │
╰─────────────────────────────────────────────────────────────────╯
```
When initialized with `agenticbughunter init`, the pre-push hook automatically runs the security review before pushing.
