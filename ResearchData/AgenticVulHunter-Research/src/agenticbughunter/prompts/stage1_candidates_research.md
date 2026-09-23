Your task is DIFF-ANCHORED vulnerability candidate localisation.

Select the strongest added lines for deeper security investigation.

The annotated Git diff is the PRIMARY and AUTHORITATIVE candidate space.

Diff markers:
- `[A,file,line]` = added
- `[D,file,line]` = deleted
- `[C,file,line]` = unchanged context

Only `[A,...]` lines may be returned as candidates.
`[D,...]` and `[C,...]` are context only.

Start by looking for eligible added lines that could plausibly be vulnerable. 

A valid candidate is an exact added statement that directly performs, constructs, transforms, decides, propagates, or executes behaviour plausibly relevant to a vulnerability mechanism.

Prefer lines that directly:
- consume or propagate externally controlled data;
- construct security-sensitive values such as paths, commands, queries, requests, destinations, permissions, or tokens;
- make security-sensitive decisions;
- invoke sensitive file, process, network, database, parser, deserialization, authentication, authorization, cryptographic, or resource operations;
- weaken, bypass, remove, or incorrectly implement a protection.

Avoid lines that are only:
- comments, blanks, imports, braces, headers, or declarations;
- simple configuration/storage assignments;
- generic `return`, `continue`, or `break`;
- logging or error reporting;
- defensive responses;
- correctly implemented validation, sanitization, escaping, rejection, or bounds checks;
- setup/plumbing or nearby contextual code.

A defensive line may be selected only when that exact line plausibly weakens or incorrectly implements the protection.

Prefer the line where the important behaviour is actually DECIDED, CONSTRUCTED, TRANSFORMED, or EXECUTED.

When several added lines implement the same mechanism, select the most direct mechanism-bearing line.

Do not select based on hypothetical behaviour alone.

REPOSITORY CONTEXT

Start from the diff.

Repository inspection is optional and must be targeted. Use it only to answer a concrete question about a plausible candidate, such as:
- what a directly called helper does;
- where a value comes from;
- whether the line reaches a sensitive operation;
- whether a directly connected guard/caller changes its meaning;
- which candidate is the stronger mechanism-bearing line.

Inspect only directly relevant symbols, callers, callees, guards, configuration, or data/control flow.

Stop once enough evidence exists to rank the candidate.

Repository context may change ranking or `selection_reason`, but it must NEVER expand the candidate space.

Do not perform the full evidence expansion that belongs to Stage 2.

Do not:
- assign a CWE;
- prove exploitability;
- perform a repository-wide vulnerability search;
- invent attacker control, missing validation, authorization bypass, injection, traversal, privilege escalation, or other unsupported vulnerability behaviour.

OUTPUT INVARIANTS

For every candidate:

- `filepath`, `changed_line`, and `statement` MUST come from the SAME `[A,file,line]` record.
- `filepath` MUST exactly match the path in the annotated diff.
- Never return absolute paths such as `/workspace/repo/...`.
- `changed_line` MUST exactly match the marker line number.
- `statement` MUST reproduce the exact added statement.
- Never relocate a finding.
- Never return an empty statement.
- `operation_type` describes what the exact statement does.
- Use `function_name: ""` when unclear.
- `selection_reason` must be concise and evidence-grounded.
- `security_relevance_score` is a ranking score in `[0,1]`, not final vulnerability confidence.

Prefer this reason format:

`observable input/state -> exact operation -> security-sensitive effect`

Do not use vague reasoning such as:

`this could potentially be exploited`

Before returning each candidate, check:

1. Is it an exact `[A,...]` executable line?
2. Does the exact statement perform or control meaningful behaviour?
3. Is its security relevance direct rather than merely contextual?
4. If repository context was needed, did it directly clarify this line?
5. Would the line still be selected without nearby security-related comments or names?
6. Is there a stronger added line representing the same mechanism?

If 1, 2, or 3 is NO, reject it.
If 6 is YES, select the stronger line.

Rank candidates from strongest/directest to weakest.

FINAL PATH CHECK:
Before producing JSON, copy `filepath` and `changed_line` again directly from the selected `[A,file,line]` marker. Ignore any absolute path shown by repository tools.

Return ONLY a JSON array:

[
  {
    "filepath": "path",
    "changed_line": 1,
    "statement": "exact added code",
    "function_name": "",
    "operation_type": "security_sensitive_decision",
    "selection_reason": "observable input/state -> exact operation -> security-sensitive effect",
    "security_relevance_score": 0.0
  }
]
