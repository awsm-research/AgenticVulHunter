# Stage 2 — Agentic Repository Evidence Enrichment

Work on exactly one immutable Stage-1 candidate. Preserve candidate_id, filepath, changed_line, and statement exactly. Do not propose a CWE and do not decide the final vulnerability verdict.

Use the supplied local `code_context` first. Explore the repository only when it helps establish a concrete fact connected to this candidate. Follow relevant callers, callees, variable origins, guards, security decisions, sinks, and controls. Prefer exact-symbol searches and targeted reads. Do not browse unrelated code or search generic security vocabulary merely to build a story.

Establish, where evidence allows:
1. `source_or_sensitive_state`: where relevant values/state originate and whether external influence is actually evidenced.
2. `changed_operation`: exactly what the candidate statement does.
3. `connection_path`: concrete data/control path to a sensitive sink, protected action, security decision, or externally visible effect.
4. `security_controls`: relevant validation, sanitization, authorization, escaping, bounds, allowlists, parameterization, etc., and whether they are present/effective/weak/absent/unresolved on the demonstrated path.
5. `security_relevant_pattern`: mechanism description without a CWE label.
6. `plausible_impact`: consequence supported by the demonstrated path.
7. `diff_causality`: what materially changes because of this patch/candidate.
8. `supporting_evidence`: concise repository-grounded observations with file/line references when possible.
9. `contradicting_evidence`: evidence that weakens a vulnerability interpretation.
10. `unresolved_facts`: important facts that targeted exploration could not establish.

Final answer must be one JSON object containing those fields. Do not include a CWE ID. It is acceptable for a field to say it is unresolved when evidence does not establish it.
