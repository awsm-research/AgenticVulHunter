# Relationship to the research implementation

AgenticBugHunter is a practical application of the supplied staged secure-code-
review research. The five-stage decomposition is retained. This refactor makes
the transport replaceable and the execution/contracts easier to inspect; it
does not claim a new vulnerability-detection method or improved benchmark scores.

## Source mapping

| Research package (`staged/`) | Application (`src/agenticbughunter/`) |
|---|---|
| `staged_qwen_agent.py` and stage runners | `pipeline.py` and `stages/base.py` |
| `agent/stage1_qwen_agent.py` | `stages/stage1_candidates.py` |
| `agent/stage2_context_agent.py` | `stages/stage2_context.py` |
| `agent/stage3_hypothesis_agent.py` | `stages/stage3_hypotheses.py` |
| `agent/stage4_judge_agent.py`, `utils/stage4_utils.py` | `stages/stage4_judge.py`, `stages/scoring.py` |
| `utils/stage5_utils.py` | `stages/stage5_filter.py` |
| `agents/*.md` | `prompts/*.md` |
| `utils/qwen_cli.py` | `llm/agent.py`, `llm/client.py`, `llm/providers.py` |

## Material differences already present in the uploads

| Concern | Supplied research harness | Supplied application / this refactor |
|---|---|---|
| Execution environment | Harbor-oriented agents and Qwen CLI | Standalone Python CLI and application-owned JSON action loop |
| Retrieval integration | Research service/tool integration | Bundled in-process BM25 retrieval |
| Stage 4 prompt | Expanded evidence-discipline/calibration prompt | Shorter application prompt, preserved in this release |
| Pair score | Equal-weight mean, rounded to 4 decimals, no caps | Mean capped by relationship and contradiction labels |
| Verdict | Fixed score bands: supported ≥0.70, uncertain ≥0.40 | Depends on configured threshold and labels |
| Stage 5 | Score threshold and comment; may report several eligible CWEs | Requires supported verdict; reports one best CWE per candidate |

The original research Stage 4 prompt is included verbatim at
`research/reference_stage4_prompt.md` for inspection. It is **not automatically
activated**. Using it while retaining the application caps would still not
reproduce the research judge. This release intentionally avoids silently
changing the judge prompt, caps, threshold, or Stage 3 methodology.

## Application scoring policy

Raw score is the mean of `exact_cwe_mechanism`, `connection`, `diff_causality`,
`security_control`, and `concrete_impact`. Each must be finite and in [0, 1].
The final score is `min(raw_score, relationship_cap, contradiction_cap)`.

| Relationship | Cap | Contradiction severity | Cap |
|---|---:|---|---:|
| exact | 1.00 | none | 1.00 |
| family_compatible | 0.79 | minor | 0.89 |
| partial | 0.59 | material | 0.69 |
| mismatch | 0.29 | fatal | 0.29 |

A supported verdict additionally requires exact/family-compatible relationship,
none/minor contradiction, and score at least the configured threshold.
The default threshold remains 0.75. These policy values come from the uploaded
application; they are not new thresholds calibrated during this refactor.

The application prompt's brief security-control wording remains a known
ambiguity relative to the supplied expanded research prompt. Evaluate any prompt
replacement as an explicit experimental change. Likewise, supported comments
may describe weaknesses prevented by fixes; a regression-only gate needs a
separately specified and evaluated review objective.

## What changed that can affect experiments

Provider adapters and clearer modules do not intentionally change the five
stage method. However, the stricter JSON parser, rejection of all-invalid
nonempty outputs, actual enforcement of final-step limits, and correction of
the context-radius limit, and aligning base evidence with the diff merge-base
can change outcomes. These are disclosed engineering
changes and must not be treated as bit-for-bit reproduction of old runs.

## Comparing judges or models fairly

Freeze the dataset commit pairs, candidate identities, Stage 2 evidence, Stage 3
hypotheses, prompts, score policy, model index, and generation/step budgets.
Judge-only studies should replay the same Stage 4 inputs, not rerun candidate
selection with each judge. Independently label both kept and discarded
hypotheses to estimate precision and recall. Report parse, localization,
transport, and timeout failures separately from supported/rejected hypotheses.

This release's offline tests verify software behavior. They do not measure CRC,
localization accuracy, CWE correctness, precision, recall, or research novelty.
There is no rerun of the supplied 144-task benchmark in this deliverable.
