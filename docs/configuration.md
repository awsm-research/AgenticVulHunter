# Configuration reference

Select a configuration file in this order: explicit `--config`, `ABH_CONFIG`,
project `.agenticbughunter.toml`, then built-in defaults. Within that selection,
`ABH_*` environment values override legacy `OPENAI_BASE_URL`, `OPENAI_API_KEY`,
`OPENAI_MODEL`, which override TOML/default values. The legacy variables do not
select a provider. Set all four connection exports when switching backends.

Exports apply to the current shell and its child processes. A TOML change is
persistent; an export can still override it. Use `config env` to inspect the
mapping and `config show` for effective values. API keys are redacted in output.

```bash
agenticbughunter config set pipeline.max_candidates 3
agenticbughunter config set pipeline.confidence_threshold 0.8
agenticbughunter config get llm.provider
export ABH_LLM_MAX_TOKENS=8000
```

`llm.extra_body` accepts a TOML inline/table object or JSON through
`ABH_LLM_EXTRA_BODY`. `config set llm.extra_body` accepts JSON and writes inline
TOML. JSON null requires the environment form because TOML has no null.
Provider-specific options are documented in [models](models.md).

## Defaults and complete environment mapping

| Setting | Default | Environment variable |
|---|---|---|
| `llm.base_url` | `http://localhost:11434/v1` | `ABH_LLM_BASE_URL` |
| `llm.api_key` | `ollama` | `ABH_LLM_API_KEY` |
| `llm.model` | `qwen3-coder:30b` | `ABH_LLM_MODEL` |
| `llm.timeout_seconds` | `300.0` | `ABH_LLM_TIMEOUT_SECONDS` |
| `llm.max_tokens` | `6000` | `ABH_LLM_MAX_TOKENS` |
| `llm.temperature` | `0.0` | `ABH_LLM_TEMPERATURE` |
| `llm.provider` | `openai` | `ABH_LLM_PROVIDER` |
| `llm.send_temperature` | `True` | `ABH_LLM_SEND_TEMPERATURE` |
| `llm.token_limit_field` | `max_tokens` | `ABH_LLM_TOKEN_LIMIT_FIELD` |
| `llm.system_role` | `system` | `ABH_LLM_SYSTEM_ROLE` |
| `llm.max_retries` | `2` | `ABH_LLM_MAX_RETRIES` |
| `llm.retry_backoff_seconds` | `1.0` | `ABH_LLM_RETRY_BACKOFF_SECONDS` |
| `llm.max_input_chars` | `240000` | `ABH_LLM_MAX_INPUT_CHARS` |
| `llm.extra_body` | `{}` | `ABH_LLM_EXTRA_BODY` |
| `bm25.top_k` | `10` | `ABH_BM25_TOP_K` |
| `bm25.max_requests_per_candidate` | `4` | `ABH_BM25_MAX_REQUESTS_PER_CANDIDATE` |
| `pipeline.max_candidates` | `5` | `ABH_PIPELINE_MAX_CANDIDATES` |
| `pipeline.max_hypotheses` | `5` | `ABH_PIPELINE_MAX_HYPOTHESES` |
| `pipeline.confidence_threshold` | `0.75` | `ABH_PIPELINE_CONFIDENCE_THRESHOLD` |
| `pipeline.max_comments` | `5` | `ABH_PIPELINE_MAX_COMMENTS` |
| `pipeline.block_on_findings` | `True` | `ABH_PIPELINE_BLOCK_ON_FINDINGS` |
| `pipeline.isolate_worktree` | `True` | `ABH_PIPELINE_ISOLATE_WORKTREE` |
| `pipeline.keep_worktree` | `False` | `ABH_PIPELINE_KEEP_WORKTREE` |
| `agents.stage1_max_steps` | `30` | `ABH_AGENTS_STAGE1_MAX_STEPS` |
| `agents.stage2_max_steps` | `30` | `ABH_AGENTS_STAGE2_MAX_STEPS` |
| `agents.stage3_max_steps` | `30` | `ABH_AGENTS_STAGE3_MAX_STEPS` |
| `agents.stage4_mode` | `api` | `ABH_AGENTS_STAGE4_MODE` |
| `agents.stage4_max_steps` | `10` | `ABH_AGENTS_STAGE4_MAX_STEPS` |
| `repository.context_radius` | `200` | `ABH_REPOSITORY_CONTEXT_RADIUS` |
| `repository.max_read_lines` | `300` | `ABH_REPOSITORY_MAX_READ_LINES` |
| `repository.max_search_results` | `30` | `ABH_REPOSITORY_MAX_SEARCH_RESULTS` |
| `ui.banner` | `True` | `ABH_UI_BANNER` |
| `ui.live_progress` | `True` | `ABH_UI_LIVE_PROGRESS` |
| `ui.show_config` | `True` | `ABH_UI_SHOW_CONFIG` |
| `ui.show_stage_details` | `True` | `ABH_UI_SHOW_STAGE_DETAILS` |

## Budget semantics

- Stage step limits count model decisions, including malformed responses.
- `llm.max_retries` counts extra HTTP attempts and is restricted to 0–5.
- `llm.max_tokens` is an output cap, not the input context-window size.
- `llm.max_input_chars` bounds total message characters and does not truncate.
- `repository.context_radius` is bounded by half the configured maximum read
  length to keep the candidate line inside the returned window.
- `bm25.max_requests_per_candidate` includes the deterministic initial query.
- The existing BM25 adapter clamps top-K to 20.
- `agents.stage4_mode=api` means a direct text judgment, not an OpenAI-only mode.
- The default `pipeline.confidence_threshold=0.75` and score caps are inherited
  application policy, not calibrated estimates of probability.

Only `ui.*` settings are presentation-only. Model, context, retrieval, stage
budget, and scoring changes can affect analysis results.
