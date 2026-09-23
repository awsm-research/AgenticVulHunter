# Stage 2 — Candidate Evidence Enrichment

Enrich one immutable Stage-1 candidate using repository evidence.

Preserve exactly:
- candidate_id
- filepath
- changed_line
- statement

Do not:
- create or relocate candidates;
- assign CWE IDs;
- decide the final vulnerability verdict;
- invent unsupported security assumptions.

Start from the candidate and existing code context.

Inspect only repository evidence directly relevant to the candidate:
- variable origins;
- data/control flow;
- callers and callees;
- enclosing conditions;
- security-sensitive operations;
- guards and security controls.

Cross files/functions only when required to establish the candidate's behaviour.

Keep exploration targeted. If an important fact cannot be established, record it in `unresolved_facts` instead of widening the search.

Establish:

1. Source/state
   - Where relevant values or security-sensitive state come from.
   - Do not call data attacker-controlled unless evidence supports it.

2. Changed operation
   - What the exact candidate statement does.
   - Describe behaviour, not CWE labels.

3. Connection
   - Whether and how the candidate reaches a sink, protected action, security decision, state change, or externally visible effect.
   - Prefer concrete paths such as:
     `request.args["cmd"] -> command -> os.system(command)`

4. Security controls
   - Identify relevant validation, sanitization, authorization, authentication, escaping, bounds checks, allowlists, parameterization, verification, permission checks, etc.
   - Describe controls as present/effective, insufficient, absent on the demonstrated path, weakened, or unresolved.

5. Risk pattern
   - Concisely describe the evidence-backed security-relevant mechanism without assigning a CWE.

6. Plausible impact
   - Describe only consequences supported by the demonstrated path.
   - Put uncertain dependencies in `unresolved_facts`.

7. Unresolved facts
   - Record material unknowns. Never guess.

Use concrete variable names, functions, conditions, and paths where supported.

Prefer:
`request.args["cmd"] -> command -> os.system(command)`

over:
`user input may reach a dangerous function`

Return ONLY one JSON object:

{
  "candidate_id": "unchanged",
  "filepath": "unchanged",
  "changed_line": 1,
  "statement": "unchanged",
  "function_name": "",
  "operation_type": "",
  "source_summary": "",
  "sink_summary": "",
  "guard_summary": "",
  "risk_pattern": "",
  "used_variable_sources": [],
  "called_function_context": [],
  "enclosing_conditions": [],
  "context_summary": "",
  "unresolved_facts": []
}