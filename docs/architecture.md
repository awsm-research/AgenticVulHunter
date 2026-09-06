# Architecture: research stages, application services, model transport

Start at `pipeline.py`. It resolves commits, creates the run log and isolated
worktree, constructs the model client, then executes Stages 1–5 sequentially.
The pipeline accepts a `ChatClient`, so a backend can change without rewriting
the stages. The CLI handles user interaction; the stages handle research logic.

## Code map

| Module | Owns | Change it when… |
|---|---|---|
| `cli.py` | Commands, setup, hooks, terminal/JSON output | Adding a command or installation behavior |
| `config.py` | Typed defaults, TOML/environment loading, validation | Adding a documented configuration field |
| `config_edit.py` | Targeted TOML edits and validation | Improving configuration editing |
| `pipeline.py` | Execution order, worktree, lifecycle, provenance | Changing orchestration or injecting a backend |
| `models.py` | Candidate, hypothesis, finding, and result records | Evolving the public data contract |
| `diff.py`, `git.py` | Commit/diff/worktree handling | Changing source revision semantics |
| `stages/stage1_candidates.py` | Changed-line selection and canonicalization | Research localization changes |
| `stages/stage2_context.py` | Evidence enrichment with immutable identity | Research context changes |
| `stages/stage3_hypotheses.py` | Local BM25 plus restricted CWE proposals | Research hypothesis changes |
| `stages/stage4_judge.py` | Pair prompts, retries, identity/schema validation | Research judge changes |
| `stages/scoring.py` | Deterministic mean, caps, verdict | Explicit scoring-policy experiments |
| `stages/stage5_filter.py` | Threshold, eligibility, sorting, final comments | Filtering/report policy changes |
| `prompts/*.md` | Model instructions for each research stage | Prompt experiments |
| `llm/types.py` | `ChatClient` protocol and normalized response | Backend integration contract changes |
| `llm/providers.py` | Provider JSON/auth/response conventions | Adding a provider |
| `llm/client.py` | HTTP, retries, timeouts, response/input budgets | Transport reliability changes |
| `llm/protocol.py` | Text action instructions and JSON parsing | Provider-neutral action-format changes |
| `llm/tools.py` | Allowlisted operation registry | Adding an explicit operation |
| `llm/agent.py` | Bounded request–observation loop | Agent execution changes |
| `tools/repo.py` | Bounded repository reads/searches | Evidence access changes |
| `tools/bm25.py`, `bm25/` | Retrieval budgets and packaged rule index | Retrieval changes |
| `runlog.py`, `ui.py` | Artifacts/events and terminal rendering | Observability/presentation changes |

Paths above are relative to `src/agenticbughunter/`.

## Stage contracts

1. Stage 1 receives an annotated Git diff and returns a list of candidate
   dictionaries. Python restores the exact statement from Git. An explicit
   empty list is valid; a nonempty list with no valid diff locations is an error.
2. Stage 2 receives one candidate at a time. It can add evidence but cannot
   change `candidate_id`, `filepath`, `changed_line`, `statement`, or
   `change_type`. Removed lines use the diff merge-base revision.
3. Stage 3 receives the enriched candidate and an initial deterministic BM25
   result. It may refine retrieval within budget. Its hypotheses must have a
   nonempty reason and use CWE IDs actually retrieved in that candidate session.
   Nonempty output with no valid hypotheses is an error; a deliberate empty
   hypothesis array is valid.
4. Stage 4 receives exactly one candidate and target CWE. The default `api`
   mode calls the text model directly and retries invalid judgments once.
   Optional `agentic` mode can resolve evidence with repository reads. Python
   validates the identity and numeric categories, then applies the existing
   application score policy.
5. Stage 5 accepts only supported assessments meeting the configured threshold
   and having nonempty comments. It selects the best CWE assessment per
   candidate, sorts candidates, and applies the comment limit.

## Agent versus provider

An agent step is a model request followed by either a final answer or one local
operation and observation. An HTTP retry repeats a failed network request; it
is not an additional reasoning step. A Stage 4 validation retry asks for a new
judgment. These three budgets are separate and should be recorded in experiments.

No provider owns repository execution. Tools are read-only and registered by
the application. Native provider function-call output is treated as a protocol
error. This keeps the method independent of Qwen CLI or any vendor agent SDK.

## Failures and reproducibility

Exceptions propagate to a saved `status=error` result and CLI exit 2. Invalid
model output must not become a successful empty review. There are still valid
empty outputs when a model deliberately proposes no candidates/hypotheses;
this is a recall question for evaluation, not a parser error.

Run provenance includes package/Python version, configured model/provider,
client type, resolved commits, judge-policy identifier, and SHA-256 hashes of
the four stage prompts. Configuration contains the execution budgets. Provider
model IDs can be moving aliases: record immutable provider model versions when
available. Prompt hashes do not replace a source revision and model-index hash
in a publication artifact; archive this release alongside evaluation results.
