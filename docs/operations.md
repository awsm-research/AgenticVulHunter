# Operating the tool

## Review and gate

`review` returns 0 when execution succeeds, even if findings exist. `gate`
returns 1 when supported findings block under the configured policy. Both return
2 for execution/configuration errors; interruption returns 130. Setting
`pipeline.block_on_findings=false` makes the gate advisory. `--json` writes
result JSON to stdout, including saved pipeline errors. Errors before the run
exists (such as invalid config) still go to stderr with exit 2.

`init --no-hook` creates project configuration and the ignored runtime directory.
Plain `init` also installs a managed pre-push hook. Use `install-hook` and
`uninstall-hook` to manage it separately. When chaining an existing shell hook, the installer preserves its original file
and replays Git's pre-push stdin independently to both hooks. The original runs
only if the review gate succeeds. Uninstall restores the original file.
Non-shell hooks are not replaced unless `--force` is explicitly passed, which
creates a backup. An already-managed hook is left in place; uninstall/reinstall
to replace a managed hook created by an older release. Test third-party hook
integrations on your environment before relying on them.

## Commit and evidence scope

The tool reviews committed refs, not the index or uncommitted files. A detached
worktree at the selected head is the default. Turning isolation off reads the
current checkout; it is only appropriate when the checkout matches the desired
head and the effects of local changes are understood.

The diff is `base...head`, so it starts at their merge-base. Reads requested with
`revision=base` now use that exact merge-base too. Run provenance records both
the selected base and the actual `diff_base_sha`, preventing old-line evidence
from being read from the wrong branch on divergent histories. An identical base/head
is an error. Distinct commits with identical trees may produce a valid empty
review without model calls. Large/binary changes need human review; the text
pipeline is not a complete binary analyzer.

## Artifacts

| File/directory in a run | Purpose |
|---|---|
| `result.json` | Pass/block/error and serialized stages/findings |
| `comments.json` | Reviewer-facing structured comments |
| `config.json` | Effective config; API-key fields redacted |
| `provenance.json` | Model, commit identities, prompt hashes, judge policy |
| `review.diff` | Reviewed Git diff |
| `run.log`, `events.jsonl` | Execution and model-call diagnostics |
| `stage*/input.json`, `output.json` | Stage boundaries |
| `stage*/candidate-*/...` | Candidate-specific conversations, retrieval, judgments |
| Agent `request.json` | Initial provider-neutral messages for inspection |

These artifacts include source code and model text. Redaction of configuration
keys does not remove secrets embedded in arbitrary source strings. Do not
publish whole run folders without reviewing their contents. Hosted models
receive the diff, selected context, and subsequent read results; local BM25
itself does not contact a service.

## Budgets and failures

| Symptom | Interpretation / action |
|---|---|
| Connection refused / timeout | Check the running model server, tunnel, base URL, and timeout |
| HTTP 401/403 | Check credentials/access; authentication failures are not retried |
| HTTP 404 | Verify provider, endpoint path, and model identifier |
| HTTP 400 unsupported parameter | Check temperature, output-limit field, system role, and extra body |
| HTTP 429 / transient 5xx | Transport retries within `max_retries`, then fails |
| Native tool-call response | Backend must return JSON actions as text, not native function calls |
| Output truncated | Raise output budget or reduce input; partial text is not accepted as final |
| Input exceeds character budget | Narrow the commit range/context or explicitly raise the budget |
| Malformed JSON / exhausted steps | Review conversation, model suitability, and step/output budgets |
| Stage 1 all candidates invalid | Model failed changed-line contract; result is error, not clean |
| Stage 3 all hypotheses invalid | Model failed retrieved-CWE contract; result is error, not clean |
| Immutable location changed | Examine Stage 2/4 response; candidate location cannot be moved |
| No comments | Could be intentional empty proposals or threshold filtering; inspect each stage |

Character budgets are deterministic safety limits, not model-specific token
estimates. The server's own context window remains authoritative. Inputs are
not silently truncated. HTTP retry backoff is capped at 30 seconds; numeric
Retry-After is honored up to that cap. Retried model requests can incur duplicate
provider cost when the earlier request completed but its response was lost.

## Minimal CI command

Install the package from a pinned release/source revision, inject the four
`ABH_LLM_*` connection settings using your CI secret configuration, fetch the
required base/head commits, and run:

```bash
agenticbughunter gate --base YOUR-BASE-REF --head YOUR-HEAD-REF --json > gate.json
```

Treat exit 2 as a failed review rather than passing the change. Keep a human
review path for false positives, fixes described as weaknesses, and incomplete
context. No GitHub, GitLab, or other service integration is required by this CLI.
