"""
ai/deep_scan.py — AI-powered deep code analysis.

Goes beyond pattern matching: sends the full file to an LLM and asks it to find
vulnerabilities that static rules miss — logic bugs, IDOR, race conditions,
auth bypasses, injection via indirect data flow, insecure crypto usage, etc.

Returns a list of Finding objects that integrate seamlessly with the existing
policy engine, watcher alerts, and audit log.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ai.client import ask_llm
from shared.models import Finding, Severity

_MAX_FILE_SIZE = 60_000  # chars — truncate to stay within context window

_DEEP_SCAN_PROMPT = """\
You are GuardRail AI, an elite application security engineer.

Analyze the source code below for security vulnerabilities that go BEYOND simple pattern matching.

Look specifically for:
1. SQL injection, command injection, XSS through indirect data flow
2. Authentication and authorization flaws (missing auth checks, IDOR)
3. Race conditions and TOCTOU bugs
4. Insecure cryptography (weak algorithms, hardcoded keys/secrets, bad randomness)
5. Hardcoded credentials, API keys, tokens, passwords
6. Unsafe deserialization (pickle, yaml.load, eval, exec)
7. Path traversal and file inclusion
8. SSRF (server-side request forgery)
9. Information leakage (verbose errors, debug endpoints, sensitive data in logs)
10. Logic flaws (broken access control, privilege escalation, business logic bypasses)
11. Missing input validation at trust boundaries
12. Insecure defaults and misconfigurations

For EACH vulnerability found, return a JSON object with exactly these keys:
  "rule_id"   — a short kebab-case identifier, e.g. "ai-sql-injection"
  "severity"  — one of: "low", "medium", "high", "critical"
  "line"      — the approximate line number (integer)
  "message"   — clear one-sentence description of the vulnerability
  "snippet"   — the exact line(s) of code that are vulnerable (max 3 lines)
  "risk"      — what can an attacker do if this is exploited
  "fix"       — concrete one-sentence remediation advice

Return ONLY a JSON array of these objects.
If the code is clean, return an empty array: []
Do NOT wrap in markdown fences. Do NOT add any text outside the JSON array.
Be precise — no false positives. Only report real, exploitable issues.

File: {file_path}

```
{code}
```
"""


def deep_scan_file(
    file_path: str | Path,
    *,
    api_key: str | None = None,
) -> list[Finding]:
    """
    Send the full source file to the LLM for deep vulnerability analysis.
    Returns Finding objects compatible with the rest of the pipeline.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    try:
        code = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if not code.strip():
        return []

    # Truncate to avoid blowing the context window
    if len(code) > _MAX_FILE_SIZE:
        code = code[:_MAX_FILE_SIZE] + "\n# ... truncated ..."

    prompt = _DEEP_SCAN_PROMPT.format(
        file_path=str(path),
        code=code,
    )

    try:
        raw_response = ask_llm(prompt, api_key=api_key)
    except Exception:
        return []

    return _parse_deep_findings(raw_response, str(path))


def _parse_deep_findings(text: str, file_path: str) -> list[Finding]:
    """Parse LLM JSON response into a list of Finding objects."""
    text = text.strip()
    # Strip markdown fences if present
    text = re.sub(r"^```(?:json)?\s*\n?", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    text = text.strip()

    try:
        items = json.loads(text)
    except json.JSONDecodeError:
        # Try to extract array from surrounding text
        match = re.search(r"\[[\s\S]*\]", text)
        if match:
            try:
                items = json.loads(match.group(0))
            except json.JSONDecodeError:
                return []
        else:
            return []

    if not isinstance(items, list):
        return []

    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            f = Finding(
                rule_id=f"ai-deep/{item.get('rule_id', 'unknown')}",
                type="ai-analysis",
                severity=_normalize_severity(item.get("severity", "medium")),
                message=_build_message(item),
                file=file_path,
                line=max(1, int(item.get("line", 1))),
                snippet=str(item.get("snippet", ""))[:500],
            )
            findings.append(f)
        except Exception:
            continue

    return findings


def _build_message(item: dict[str, Any]) -> str:
    """Compose a rich message from the LLM finding."""
    msg = str(item.get("message", "AI-detected vulnerability"))
    risk = item.get("risk", "")
    fix = item.get("fix", "")

    parts = [msg]
    if risk:
        parts.append(f"Risk: {risk}")
    if fix:
        parts.append(f"Fix: {fix}")
    return " | ".join(parts)


def _normalize_severity(val: Any) -> str:
    if isinstance(val, str):
        val = val.lower().strip()
        if val in {"low", "medium", "high", "critical"}:
            return val
    return "medium"
