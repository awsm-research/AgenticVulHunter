# Development and validation

## Install and test

```bash
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
python -m pip wheel . --no-deps -w dist
```

Runtime uses the Python standard library and bundled BM25 assets. Building the
package requires the setuptools version declared in `pyproject.toml`. Development
and packaging should use Python 3.11 or newer. Git is an external prerequisite.

## What the test suite proves

- Existing configuration/UI and BM25 tests still pass.
- Provider payloads contain normal text messages, with provider-specific role,
  authentication, parameter, and response normalization.
- HTTP 429 retries are bounded; authentication errors are not retried.
- Empty, truncated, refused, and native tool-call responses are not clean results.
- Agent observations return to the model; unknown operations cannot execute.
- Invalid arrays, batches of actions, null finals, and exhausted steps fail safely.
- Environment exports load correctly and cannot mask invalid persisted edits.
- Real temporary Git repositories and the actual bundled BM25 index execute all
  five stages with a scripted text model.
- Candidate statements are restored from Git; invalid locations fail the run.
- Detached worktrees are removed after success and failure.
- Divergent histories record the actual diff merge-base.
- Pre-push hook chaining gives both hooks the original stdin and restores the
  original hook when uninstalled.
- Existing application score caps are retained; invalid numeric scores fail.

The scripted model deliberately returns fixtures. These tests do not establish
model accuracy, live endpoint availability, or research benchmark performance.
Run `doctor --check-llm` against each actual deployment. Then run a small labeled
repository set before a full model comparison or push-gate rollout.

## Add a provider

1. Implement pure request/response mappings in `llm/providers.py`, or supply a
   custom `ChatClient` to `SecureReviewPipeline` from Python.
2. Extend config validation and document the endpoint and auth requirements.
3. Add request/response fixtures and failure-mode tests. Do not bake model IDs
   or provider-native tools into a research stage.
4. Validate with a live compatibility check using your own authorized key.

## Add a tool

Implement a bounded read-only handler taking a dictionary and returning a
JSON-serializable observation. Register a `Tool` with the intended stage's
registry. Validate arguments in the handler, preserve repository boundaries,
and add a test proving both normal operation and rejection of invalid inputs.
The model may propose an operation but cannot create a new handler or execute
an arbitrary shell command through the agent protocol.

## Change a research stage

Keep the stage input/output contract explicit. Add a regression test for any
new invariant. Update prompt hashes through a new run; do not edit saved runs
to pretend they used new instructions. Record prompt, policy, retrieval-index,
and model changes separately from transport refactors. Rerun the relevant
labeled evaluation before making accuracy claims.

## Release hygiene

Do not package `.git`, old run directories, API keys, caches, or environment
files. Include the source, tests, documentation, and bundled BM25 data. Preserve
the source release and benchmark configuration for reproducibility. This
refactor adds no license grant; confirm the project's and bundled rule data's
licensing before public redistribution.
