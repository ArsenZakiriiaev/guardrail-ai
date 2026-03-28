from __future__ import annotations

import re


SENSITIVE_SNIPPET_PLACEHOLDER = "Sensitive value redacted."

_SENSITIVE_TYPES = {"secret", "credential"}
_SENSITIVE_RULE_MARKERS = (
    "secret",
    "password",
    "passwd",
    "credential",
    "token",
    "aws-key",
    "api-key",
    "private-key",
)
_AWS_ACCESS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
_ASSIGNMENT_STRING_PATTERN = re.compile(r'=\s*(?P<quote>["\']).*?(?P=quote)')


def is_sensitive_finding(finding_type: str, rule_id: str) -> bool:
    normalized_type = (finding_type or "").strip().lower()
    normalized_rule_id = (rule_id or "").strip().lower()

    return normalized_type in _SENSITIVE_TYPES or any(
        marker in normalized_rule_id for marker in _SENSITIVE_RULE_MARKERS
    )


def sanitize_snippet(snippet: str, finding_type: str, rule_id: str) -> str:
    cleaned = (snippet or "").strip()
    if not cleaned:
        return ""

    if not is_sensitive_finding(finding_type, rule_id):
        return cleaned

    redacted = cleaned
    changed = False

    redacted, aws_replacements = _AWS_ACCESS_KEY_PATTERN.subn("<redacted>", redacted)
    changed = changed or aws_replacements > 0

    redacted, assignment_replacements = _ASSIGNMENT_STRING_PATTERN.subn(
        lambda match: f'= {match.group("quote")}<redacted>{match.group("quote")}',
        redacted,
    )
    changed = changed or assignment_replacements > 0

    if changed:
        return redacted

    return SENSITIVE_SNIPPET_PLACEHOLDER
