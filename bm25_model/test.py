from __future__ import annotations

import json
import sys
from typing import Any

import requests


RETRIEVER_URL = "http://localhost:5056/predict"
TOP_K = 5
TIMEOUT_SECONDS = 30


TEST_CASES: list[dict[str, Any]] = [
    {
        "name": "HTTP response splitting",
        "expected_cwes": {"CWE-113"},
        "should_skip": False,
        "item": {
            "filepath": "web/response.py",
            "changed_line": 42,
            "statement": "response.headers[name] = value",
            "language": "python",
            "operation_type": "web_output",
            "selection_reason": (
                "A caller-provided value is written into an HTTP response "
                "header without visible CRLF validation."
            ),
            "source_summary": "value supplied by an external caller",
            "sink_summary": "HTTP response header assignment",
            "guard_summary": "no carriage-return or newline validation visible",
            "risk_pattern": (
                "untrusted input written to a response header may permit "
                "header injection or response splitting"
            ),
            "called_apis": ["response.headers"],
            "context_summary": (
                "The setter stores the supplied value directly in the "
                "outgoing response header collection."
            ),
        },
    },
    {
        "name": "SQL injection",
        "expected_cwes": {"CWE-89"},
        "should_skip": False,
        "item": {
            "filepath": "db/users.py",
            "changed_line": 88,
            "statement": 'cursor.execute("SELECT * FROM users WHERE name = \'" + username + "\'")',
            "language": "python",
            "operation_type": "database_operation",
            "selection_reason": (
                "User-controlled input is concatenated into an SQL query "
                "executed by the database."
            ),
            "source_summary": "username from an HTTP request parameter",
            "sink_summary": "database cursor execute operation",
            "guard_summary": "no parameterized query",
            "risk_pattern": "SQL query construction using untrusted input",
            "called_apis": ["cursor.execute"],
            "context_summary": (
                "The query string is constructed with string concatenation "
                "and sent directly to the database."
            ),
        },
    },
    {
        "name": "Command injection",
        "expected_cwes": {"CWE-78"},
        "should_skip": False,
        "item": {
            "filepath": "tools/archive.py",
            "changed_line": 31,
            "statement": 'subprocess.run("tar -xf " + filename, shell=True)',
            "language": "python",
            "operation_type": "command_execution",
            "selection_reason": (
                "An externally supplied filename is concatenated into a "
                "shell command."
            ),
            "source_summary": "filename supplied through a request",
            "sink_summary": "shell command execution",
            "guard_summary": "no argument separation or shell escaping",
            "risk_pattern": "untrusted input reaches a shell command",
            "called_apis": ["subprocess.run"],
            "context_summary": (
                "The command is executed with shell=True after concatenating "
                "the input filename."
            ),
        },
    },
    {
        "name": "Path traversal",
        "expected_cwes": {"CWE-22"},
        "should_skip": False,
        "item": {
            "filepath": "files/download.py",
            "changed_line": 57,
            "statement": "return open(os.path.join(upload_dir, requested_name), 'rb')",
            "language": "python",
            "operation_type": "file_operation",
            "selection_reason": (
                "A user-controlled filename is joined with a trusted base "
                "directory and opened without a containment check."
            ),
            "source_summary": "requested_name from the URL path",
            "sink_summary": "filesystem open operation",
            "guard_summary": "no canonical path containment validation",
            "risk_pattern": "untrusted path may escape the intended directory",
            "called_apis": ["os.path.join", "open"],
            "context_summary": (
                "The constructed path is opened directly without resolving "
                "and checking that it remains under upload_dir."
            ),
        },
    },
    {
        "name": "Unsafe deserialization",
        "expected_cwes": {"CWE-502"},
        "should_skip": False,
        "item": {
            "filepath": "sessions/storage.py",
            "changed_line": 73,
            "statement": "session = pickle.loads(request.data)",
            "language": "python",
            "operation_type": "deserialization",
            "selection_reason": (
                "Untrusted request bytes are deserialized with pickle."
            ),
            "source_summary": "raw HTTP request body",
            "sink_summary": "pickle deserialization",
            "guard_summary": "no trusted signature or safe format validation",
            "risk_pattern": "unsafe deserialization of attacker-controlled data",
            "called_apis": ["pickle.loads"],
            "context_summary": (
                "The complete request body is passed directly to "
                "pickle.loads."
            ),
        },
    },
    {
        "name": "Weak CORS origin check",
        "expected_cwes": {"CWE-346"},
        "should_skip": False,
        "item": {
            "filepath": "web/cors.py",
            "changed_line": 26,
            "statement": 'if origin.startswith("https://trusted.example"):',
            "language": "python",
            "operation_type": "authorization",
            "selection_reason": (
                "A weak prefix comparison is used to authorize a "
                "user-controlled Origin header."
            ),
            "source_summary": "Origin request header",
            "sink_summary": "CORS authorization decision",
            "guard_summary": "prefix comparison instead of exact origin parsing",
            "risk_pattern": "attacker-controlled origin may bypass CORS policy",
            "called_apis": ["str.startswith"],
            "context_summary": (
                "An origin such as trusted.example.attacker.test may satisfy "
                "the prefix check."
            ),
        },
    },
    {
        "name": "Class header must be skipped",
        "expected_cwes": set(),
        "should_skip": True,
        "item": {
            "filepath": "bottle.py",
            "changed_line": 1114,
            "statement": "class HeaderProperty(object):",
            "language": "python",
            "operation_type": "",
            "selection_reason": "",
            "source_summary": "",
            "sink_summary": "",
            "guard_summary": "",
            "risk_pattern": "",
            "called_apis": [],
            "context_summary": (
                "This is only a class declaration and performs no operation."
            ),
        },
    },
    {
        "name": "Function header must be skipped",
        "expected_cwes": set(),
        "should_skip": True,
        "item": {
            "filepath": "bottle.py",
            "changed_line": 1124,
            "statement": "def __set__(self, obj, value):",
            "language": "python",
            "operation_type": "",
            "selection_reason": "",
            "source_summary": "",
            "sink_summary": "",
            "guard_summary": "",
            "risk_pattern": "",
            "called_apis": [],
            "context_summary": (
                "This is only a function declaration and performs no "
                "sensitive operation."
            ),
        },
    },
    {
        "name": "LocalRequest lexical trap",
        "expected_cwes": set(),
        "forbidden_cwes": {"CWE-563"},
        "should_skip": True,
        "item": {
            "filepath": "bottle.py",
            "changed_line": 1327,
            "statement": "class LocalRequest(BaseRequest, threading.local):",
            "language": "python",
            "operation_type": "",
            "selection_reason": "",
            "source_summary": "",
            "sink_summary": "",
            "guard_summary": "",
            "risk_pattern": "",
            "called_apis": ["threading.local"],
            "context_summary": (
                "LocalRequest is a class name. It does not define an unused "
                "local variable."
            ),
        },
    },
    {
        "name": "Parameterized SQL safe negative",
        "expected_cwes": set(),
        "forbidden_cwes": {"CWE-89"},
        "should_skip": False,
        "item": {
            "filepath": "db/users.py",
            "changed_line": 102,
            "statement": (
                'cursor.execute("SELECT * FROM users WHERE name = ?", '
                "(username,))"
            ),
            "language": "python",
            "operation_type": "database_operation",
            "selection_reason": (
                "The changed line uses a parameterized SQL query."
            ),
            "source_summary": "username from an HTTP request parameter",
            "sink_summary": "database cursor execute operation",
            "guard_summary": "input is passed as a bound query parameter",
            "risk_pattern": "parameterized query prevents SQL syntax injection",
            "called_apis": ["cursor.execute"],
            "context_summary": (
                "The SQL text and external value are passed separately to "
                "the database driver."
            ),
        },
    },
]


def find_predictions(response: Any) -> list[dict[str, Any]]:
    """Handle common server response shapes."""

    if isinstance(response, list):
        return [
            item for item in response
            if isinstance(item, dict)
        ]

    if not isinstance(response, dict):
        return []

    for key in ("predictions", "results", "items"):
        value = response.get(key)
        if isinstance(value, list):
            return [
                item for item in value
                if isinstance(item, dict)
            ]

    # Some servers return one prediction object directly.
    if "top_sast_rules" in response:
        return [response]

    return []


def rule_cwe(rule: dict[str, Any]) -> str:
    value = str(rule.get("cwe_id") or "").strip().upper()

    if value and not value.startswith("CWE-") and value.isdigit():
        return f"CWE-{value}"

    return value


def display_rule(rule: dict[str, Any], rank: int) -> None:
    cwe = rule_cwe(rule) or "UNKNOWN"
    rule_id = rule.get("rule_id") or "unknown-rule"

    relative_score = rule.get(
        "relative_bm25_score",
        rule.get("score"),
    )
    raw_score = rule.get("raw_bm25_score")

    print(
        f"    {rank}. {cwe:<8} "
        f"{rule_id} "
        f"relative={relative_score!r} "
        f"raw={raw_score!r}"
    )


def evaluate_case(
    test_case: dict[str, Any],
    prediction: dict[str, Any],
) -> bool:
    rules = prediction.get("top_sast_rules")
    if not isinstance(rules, list):
        rules = []

    retrieved_cwes = {
        rule_cwe(rule)
        for rule in rules
        if isinstance(rule, dict) and rule_cwe(rule)
    }

    retrieval_skipped = bool(
        prediction.get("retrieval_skipped")
    )

    should_skip = bool(test_case.get("should_skip"))
    expected_cwes = set(test_case.get("expected_cwes", set()))
    forbidden_cwes = set(test_case.get("forbidden_cwes", set()))

    passed = True
    reasons: list[str] = []

    if should_skip:
        if retrieval_skipped or not rules:
            reasons.append("invalid candidate correctly skipped")
        else:
            passed = False
            reasons.append("invalid candidate produced retrieval results")

    if expected_cwes:
        matched = expected_cwes & retrieved_cwes
        if matched:
            reasons.append(
                f"expected CWE retrieved: {sorted(matched)}"
            )
        else:
            passed = False
            reasons.append(
                f"expected one of {sorted(expected_cwes)}, "
                f"received {sorted(retrieved_cwes)}"
            )

    forbidden_matches = forbidden_cwes & retrieved_cwes
    if forbidden_matches:
        passed = False
        reasons.append(
            f"forbidden lexical match returned: "
            f"{sorted(forbidden_matches)}"
        )

    if (
        not should_skip
        and not expected_cwes
        and not forbidden_matches
    ):
        reasons.append("no forbidden CWE found")

    print(f"  Status: {'PASS' if passed else 'FAIL'}")
    print(f"  Skipped: {retrieval_skipped}")

    skip_reason = prediction.get("retrieval_skip_reason")
    if skip_reason:
        print(f"  Skip reason: {skip_reason}")

    if rules:
        print("  Retrieved rules:")
        for rank, rule in enumerate(rules, start=1):
            if isinstance(rule, dict):
                display_rule(rule, rank)
    else:
        print("  Retrieved rules: none")

    print(f"  Check: {'; '.join(reasons)}")
    return passed


def main() -> int:
    payload = {
        "items": [
            test_case["item"]
            for test_case in TEST_CASES
        ],
        "top_k": TOP_K,
    }

    print(f"Sending {len(TEST_CASES)} cases to:")
    print(f"  {RETRIEVER_URL}\n")

    try:
        response = requests.post(
            RETRIEVER_URL,
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"Retriever request failed: {exc}", file=sys.stderr)
        return 1

    try:
        response_data = response.json()
    except ValueError:
        print("Server returned non-JSON output:", file=sys.stderr)
        print(response.text, file=sys.stderr)
        return 1

    predictions = find_predictions(response_data)

    if len(predictions) != len(TEST_CASES):
        print(
            "Unexpected prediction count: "
            f"expected {len(TEST_CASES)}, "
            f"received {len(predictions)}",
            file=sys.stderr,
        )
        print(json.dumps(response_data, indent=2))
        return 1

    passed_count = 0

    for index, (test_case, prediction) in enumerate(
        zip(TEST_CASES, predictions),
        start=1,
    ):
        print("=" * 80)
        print(f"Test {index}: {test_case['name']}")

        if evaluate_case(test_case, prediction):
            passed_count += 1

    print("=" * 80)
    print(
        f"Summary: {passed_count}/{len(TEST_CASES)} tests passed"
    )

    return 0 if passed_count == len(TEST_CASES) else 2


if __name__ == "__main__":
    raise SystemExit(main())