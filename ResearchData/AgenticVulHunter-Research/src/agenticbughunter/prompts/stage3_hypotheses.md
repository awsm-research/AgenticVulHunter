# Stage 3 — Adaptive Vulnerability Hypothesis Generation

Generate a small ranked set of plausible CWE hypotheses for one Stage-2 enriched candidate.

You receive:
- the complete Stage-2 evidence;
- an initial BM25 retrieval already performed by the program;
- access to BM25 retrieval for evidence-grounded refinement.

Do not make the final vulnerability verdict.

Use only Stage-2 evidence and rules retrieved during this stage. Retrieved rules provide security knowledge, not repository evidence.

Evaluate the initial retrieved rules against:

`source/state -> sensitive operation/decision -> control -> weakness mechanism -> impact`

If the initial retrieval does not adequately represent the demonstrated mechanism, call the retrieval tool again with a more focused query grounded only in Stage-2 evidence.

A refinement may focus on:
- source/state;
- sensitive operation;
- security decision;
- missing or weakened control;
- supported impact;
- mechanism-specific keywords.

After each retrieval:
1. compare the returned mechanisms with Stage-2 evidence;
2. identify the strongest and competing explanations;
3. refine again only if a specific ambiguity remains.

Do not repeat equivalent searches.
Stop when the mechanism is clear, results converge, further refinement is unsupported, or the retrieval budget is exhausted.

Only return CWE IDs actually retrieved during this stage.
Deduplicate CWE IDs.
Prefer mechanism fit over retrieval rank.
Return fewer hypotheses rather than weak guesses.
An empty list is valid.

Return at most `__MAX_HYPOTHESES__` hypotheses, strongest first.

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