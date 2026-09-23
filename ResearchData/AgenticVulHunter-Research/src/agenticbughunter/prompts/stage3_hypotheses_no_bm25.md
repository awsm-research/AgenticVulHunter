# Stage 3 — Model-Only CWE Hypotheses

Identify the CWE types supported by one Stage-2 enriched candidate.

You receive only the complete Stage-2 evidence. BM25, SAST-rule retrieval, and adaptive retrieval are disabled for this ablation. Do not use tools and do not make the final vulnerability verdict.

The supplied evidence includes, when established by Stage 2:

- candidate identity, file path, changed line, changed statement, and change type;
- function name, operation type, and the surrounding code context;
- source/state origins and the variables used by the changed operation;
- sink, protected action, security decision, state change, or visible effect;
- callers, callees, enclosing conditions, and the demonstrated connection;
- validation, sanitization, authorization, escaping, bounds checks, allowlists,
  parameterization, verification, and other relevant controls;
- the evidence-backed risk mechanism and context summary; and
- unresolved facts that limit what can be concluded.

Use all supplied Stage-2 evidence as one record. Anchor every proposal to the
exact candidate line and its demonstrated repository context. Do not relocate the
candidate, invent missing data flow, treat an unresolved fact as established, or
infer a CWE from the changed statement alone when the surrounding evidence does
not support the mechanism.

Infer the CWE directly from this evidence chain:

`source/state -> sensitive operation/decision -> control -> weakness mechanism -> impact`

Return each distinct CWE hypothesis supported by the evidence, strongest first.
Do not target a particular number of hypotheses, pad the result, or add speculative
alternatives. An empty list is valid when the evidence supports no plausible weakness.

For each proposal, make `fit_reason` a compact evidence chain using concrete names
from the Stage-2 record, for example:

`request.args["path"] -> filename -> open(filename), with no path-boundary check`

Return ONLY:

{
  "hypotheses": [
    {
      "cwe_id": "CWE-22",
      "cwe_name": "Path Traversal",
      "fit_reason": "Concise Stage-2 evidence -> mechanism match"
    }
  ]
}
