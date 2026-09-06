# Model portability

The invariant is `chat(messages) -> LLMResponse(content=...)`. Stages never call
a provider SDK or consume a provider-native tool-call object.

The agent writes an action as ordinary JSON text. AgenticBugHunter validates it,
executes an allowlisted local operation, and returns an observation in another
ordinary chat message. A model needs text generation, instruction following,
sufficient context capacity, and reasonably reliable JSON; it does not need a
native function-calling feature. Portability is an interface property, not a
promise of equal detection quality across models.

## OpenAI-compatible endpoint

```bash
export ABH_LLM_PROVIDER="openai"
export ABH_LLM_BASE_URL="https://YOUR-ENDPOINT/v1"
export ABH_LLM_MODEL="MODEL-ID-AVAILABLE-TO-YOU"
export ABH_LLM_API_KEY="YOUR-KEY"
agenticbughunter doctor --check-llm
```

The base URL may instead be a full URL ending in `/chat/completions`. The app
sends `model`, ordinary `messages`, an output limit, and optionally temperature.
It never sends `tools`, `tool_choice`, or `response_format` by default.

The local default remains `http://localhost:11434/v1` with `qwen3-coder:30b` for
backward compatibility. A forwarded server may use port 11435, as in the quick
start. These are configuration examples, not services started by the tool.

Some endpoints/model families require different request parameters:

```bash
export ABH_LLM_SEND_TEMPERATURE=false
export ABH_LLM_TOKEN_LIMIT_FIELD=max_completion_tokens
# Only when your endpoint needs a developer instruction role:
export ABH_LLM_SYSTEM_ROLE=developer
```

`token_limit_field` can also be an empty string to omit the output-limit field.
`system_role=user` folds instructions into the first user turn for APIs that do
not accept system messages. This can weaken instruction separation; it is
explicitly opt-in. Unset these overrides when switching to a different model.

## Anthropic Messages

```bash
export ABH_LLM_PROVIDER="anthropic"
export ABH_LLM_BASE_URL="https://api.anthropic.com/v1"
export ABH_LLM_MODEL="YOUR-CLAUDE-MODEL-ID"
export ABH_LLM_API_KEY="YOUR-ANTHROPIC-KEY"
agenticbughunter doctor --check-llm
```

The adapter separates the system instruction, combines adjacent same-role
turns, uses `x-api-key`, and extracts only text answer blocks. Native thinking
blocks are not interpreted as agent actions. The transport follows the
[Messages API](https://platform.claude.com/docs/en/api/messages/create).
Set `ABH_LLM_SEND_TEMPERATURE=false` if the chosen model requires omission.

## Gemini generateContent

```bash
export ABH_LLM_PROVIDER="gemini"
export ABH_LLM_BASE_URL="https://generativelanguage.googleapis.com/v1beta"
export ABH_LLM_MODEL="YOUR-GEMINI-MODEL-ID"
export ABH_LLM_API_KEY="YOUR-GEMINI-KEY"
agenticbughunter doctor --check-llm
```

The adapter maps assistant turns to `model`, sends instructions separately,
and uses the `x-goog-api-key` header. It extracts answer text rather than thought
parts. Its wire format follows the
[generateContent API](https://ai.google.dev/api/generate-content).

## Provider-specific options

Supply extra JSON fields without changing a stage:

```bash
export ABH_LLM_EXTRA_BODY='{"generationConfig":{"topP":0.9}}'
```

This example is Gemini-specific. Extensions merge one dictionary level into
the request. Invalid or unsupported options are reported as provider errors;
the client does not silently remove them. Changes to the model, messages,
tools, streaming, and top-level candidate count are reserved. Keep one response
candidate and non-streaming text. Advanced thinking/reasoning options still need
to be appropriate for your chosen model and output budget.

## Add any other backend in Python

```python
from agenticbughunter.config import Config
from agenticbughunter.llm import LLMResponse
from agenticbughunter.pipeline import SecureReviewPipeline

class MyBackend:
    def chat(self, messages, *, temperature=None, max_tokens=None, metadata=None):
        # Call your local model or SDK here. Return the final answer TEXT.
        # The pipeline expects JSON actions/final values in that text.
        text = your_model_generate(messages)
        return LLMResponse(content=text, usage={}, raw={}, duration_ms=0.0)

cfg = Config()
cfg.llm.model = "my-backend-model"  # Recorded in run provenance.
result = SecureReviewPipeline(cfg, client=MyBackend()).run(
    "/path/to/repository", base="HEAD~1", head="HEAD"
)
```

`your_model_generate` is the integration point to implement, not a supplied
function. Custom clients own their timeouts, budgets, retries, and provider
logging. The built-in HTTP client enforces those centrally. Custom injection is
available through Python, not a dynamic import string in repository config.

## Text action contract

```json
{"type":"tool","tool":"read_file","arguments":{"path":"app.py","start_line":1,"end_line":60}}
```

After the observation, return another action or a final object/array matching
the stage prompt. `{"type":"final","answer": ...}` is also accepted.

The runner rejects multiple actions in one response, malformed arrays, unknown
actions, and primitive final answers. It never executes a tool on the final
allowed step. It does not salvage a valid-looking candidate nested inside a
broken JSON response. A complete leading `<think>...</think>` block and a single
JSON code fence can be handled, but the requested output is plain JSON.
