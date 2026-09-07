# Stage 4 — Evidence-Grounded Candidate × CWE Judge

Judge exactly one immutable candidate against exactly one supplied target CWE. Preserve candidate_id, filepath, changed_line, statement, and target cwe_id exactly. Never relocate the finding and never substitute another CWE.

Score five evidence categories from 0.00 to 1.00, each with concrete evidence:
1. exact_cwe_mechanism — does demonstrated behaviour satisfy defining properties of this exact CWE?
2. connection — is attacker-controlled input or security-sensitive state concretely connected to the relevant sink/action/decision/state?
3. diff_causality — did this patch materially create, expose, remove, weaken, or add protection for the mechanism? State the revert counterfactual.
4. security_control — how strongly does evidence establish that the exact CWE's required validation/sanitization/auth/escaping/bounds/etc. is missing, weakened, bypassable, removed, or newly added?
5. concrete_impact — is the claimed consequence concretely supported rather than only theoretically possible?

Also provide strongest supporting evidence and strongest contradicting evidence. Do not manufacture either. A dangerous API or retrieved CWE label alone is not enough. Defensive code may reveal vulnerable behaviour it prevents; do not automatically call the defensive line itself a vulnerability.

For `security_control`, identify the required control, why this exact CWE requires it, which local or downstream controls were examined, and the demonstrated deficiency. A score above 0.60 is invalid unless all four are concrete and evidence-grounded. The absence of an arbitrary check does not itself prove vulnerability.

If downstream validation, attacker control, reachability, or concrete impact is an essential unresolved fact, keep the relevant category scores low enough that the arithmetic mean remains below the support threshold. A supported review comment must describe demonstrated impact rather than depend on an unknown condition.

CWE relationship must be exactly one of: exact, family_compatible, partial, mismatch.
Contradiction severity must be exactly one of: none, minor, material, fatal.

Do NOT output overall confidence/score; the program computes the arithmetic mean of the five category scores deterministically.

`review_comment` should be 2-4 concise actionable sentences only when evidence supports a useful security finding. Otherwise return an empty string.

Final answer must be exactly one JSON object:
{
  "candidate_id": "unchanged",
  "filepath": "unchanged",
  "changed_line": 1,
  "statement": "unchanged",
  "cwe_id": "CWE-000",
  "cwe_name": "",
  "cwe_relationship": "exact|family_compatible|partial|mismatch",
  "category_scores": {
    "exact_cwe_mechanism": {"score": 0.0, "evidence": ""},
    "connection": {"score": 0.0, "evidence": ""},
    "diff_causality": {"score": 0.0, "evidence": ""},
    "security_control": {
      "score": 0.0,
      "evidence": "",
      "required_control": "",
      "control_requirement_evidence": "",
      "existing_controls_checked": [],
      "deficiency_evidence": ""
    },
    "concrete_impact": {"score": 0.0, "evidence": ""}
  },
  "diff_counterfactual": "If the candidate line were reverted, ...",
  "supporting_evidence": [],
  "contradicting_evidence": [],
  "contradiction_severity": "none|minor|material|fatal",
  "unresolved_facts": [],
  "review_comment": ""
}
