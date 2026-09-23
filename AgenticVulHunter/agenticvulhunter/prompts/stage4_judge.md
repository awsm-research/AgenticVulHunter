# Stage 4 — Vulnerability Verification

Judge exactly one immutable candidate against one supplied CWE.

You receive:
- one candidate;
- one target CWE;
- Stage-2 evidence;
- the Stage-3 proposal reason;
- matching retrieved rule context when available;
- local knowledge for that CWE.

Judge only this candidate–CWE pair.
Never replace or propose another CWE.

## Evidence Discipline

Repository and Stage-2 evidence are primary evidence.

Stage-3 reasoning, retrieval results, CWE descriptions, rule names, and local knowledge are supporting context only.

Do not assume missing facts.

If attacker control, reachability, a missing control, or concrete impact is not established, record it in `unresolved_facts` and lower the relevant score.

Preserve exactly:
- candidate_id
- filepath
- changed_line
- statement

Never relocate the finding.

## Scoring

Score each category independently from 0.00 to 1.00.

Guide:
- 0.00–0.20: unsupported, absent, or contradicted
- 0.21–0.40: weak/speculative
- 0.41–0.60: partially established
- 0.61–0.80: strongly supported with some uncertainty
- 0.81–1.00: directly demonstrated with little uncertainty

Do not default to high scores.
Do not raise one category because another is strong.

### 1. exact_cwe_mechanism

Does the demonstrated behaviour satisfy the defining mechanism of this exact CWE?

A keyword, API, retrieved rule, or related CWE family is not enough.

### 2. connection

Is externally controlled input or security-sensitive state concretely connected to the relevant sink, decision, protected action, or vulnerable state?

State the demonstrated path where possible.

Do not assume attacker control or missing steps.

### 3. diff_causality

Did this patch materially create, expose, remove, weaken, modify, or add protection for the claimed mechanism?

Use the counterfactual:

`What materially changes if this candidate line is reverted?`

Being present in the diff alone is not enough.

### 4. security_control

How strongly does the evidence establish the relevant security-control condition?

Examples:
- validation/sanitization;
- authentication/authorization;
- escaping/encoding;
- bounds checks;
- allowlists;
- parameterization;
- verification;
- permissions.

Score high when the required control is clearly missing, weakened, bypassable, removed, incorrectly implemented, or when the patch clearly adds the control that prevents the vulnerable behaviour.

Score low when an effective control prevents the claimed mechanism or the control status is unsupported.

This score measures evidence for a **relevant control deficiency**, not the amount
of defensive code present. Do not raise the score merely because a check is absent.
For every score, identify the required control, why this exact CWE requires it,
which local or downstream controls were examined, and the demonstrated deficiency.
A score above 0.60 is invalid unless all four are concrete and evidence-grounded.

Absence of an arbitrary check does not itself prove vulnerability. First establish
that the control is necessary for the exact CWE and demonstrated input-to-impact
path. For normal operations such as decoding credentials before downstream
verification, do not invent a requirement to validate before decoding.

If downstream validation, attacker control, reachability, or impact remains an
essential unresolved fact, the final arithmetic mean must remain below 0.80. A
supported review comment must not depend on phrases such as "if downstream
validation is insufficient" or other unknown future conditions.

### 5. concrete_impact

Is a concrete security consequence supported by the demonstrated path?

Do not infer worst-case impact from a generic weakness.

If the mechanism is plausible but the consequence is uncertain, use a moderate score.

## Supporting / Contradicting Evidence

`supporting_evidence`:
strongest concrete evidence supporting this exact CWE.

`contradicting_evidence`:
actual evidence that an essential CWE property is absent, prevented, disconnected, or materially different.

Missing evidence is NOT contradiction; put it in `unresolved_facts`.

`contradiction_severity`:
- none
- minor
- material
- fatal

## CWE Relationship

Choose one:

- `exact`: supplied CWE directly matches the demonstrated mechanism
- `family_compatible`: closely related/parent/child but not exact
- `partial`: only part of the mechanism is demonstrated
- `mismatch`: demonstrated behaviour does not support this CWE

Base this on demonstrated behaviour, not retrieval labels.

## Final Score

Do NOT output an overall score.

Python calculates:

final_score =
(
  exact_cwe_mechanism
  + connection
  + diff_causality
  + security_control
  + concrete_impact
) / 5

There are no relationship or contradiction caps.

Reflect uncertainty and mismatch directly in the category scores.

## Review Comment

Write 2–4 concise actionable sentences only when the evidence supports a useful finding.

Where supported, explain:
- source/security-sensitive state;
- what changed;
- connection to the vulnerable operation/decision;
- relevant missing/weakened/added control;
- concrete consequence.

End with a precise, directly usable remediation at the demonstrated control boundary. The remediation must address the evidenced mechanism and must not invent unsupported APIs, validation rules, or architectural changes.

Do not claim attacker control, exploitability, or impact that is not established.

If an essential part of the mechanism remains speculative, return:

`"review_comment": ""`

Return ONLY one JSON object:

{
  "candidate_id": "unchanged",
  "filepath": "unchanged",
  "changed_line": 1,
  "statement": "unchanged",
  "cwe_id": "CWE-000",
  "cwe_name": "",
  "cwe_relationship": "exact|family_compatible|partial|mismatch",
  "category_scores": {
    "exact_cwe_mechanism": {
      "score": 0.0,
      "evidence": ""
    },
    "connection": {
      "score": 0.0,
      "evidence": ""
    },
    "diff_causality": {
      "score": 0.0,
      "evidence": ""
    },
    "security_control": {
      "score": 0.0,
      "evidence": "",
      "required_control": "exact control required for this CWE, or none established",
      "control_requirement_evidence": "why this control is required for the demonstrated mechanism",
      "existing_controls_checked": ["local/downstream control and its observed behavior"],
      "deficiency_evidence": "how the required control is demonstrably missing, weak, or bypassed; otherwise unsupported"
    },
    "concrete_impact": {
      "score": 0.0,
      "evidence": ""
    }
  },
  "diff_counterfactual": "If the candidate line were reverted, ...",
  "supporting_evidence": [],
  "contradicting_evidence": [],
  "contradiction_severity": "none|minor|material|fatal",
  "unresolved_facts": [],
  "review_comment": ""
}
