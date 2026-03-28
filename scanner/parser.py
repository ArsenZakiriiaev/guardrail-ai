"""
scanner/parser.py — парсит JSON-ответ Semgrep в список Finding.
"""

from pathlib import Path
from typing import List

from shared.models import Finding, Severity
from shared.redaction import (
    SENSITIVE_SNIPPET_PLACEHOLDER,
    is_sensitive_finding,
    sanitize_snippet,
)


# Маппинг severity из Semgrep в наш Enum
_SEVERITY_MAP = {
    "INFO": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def parse_findings(semgrep_output: dict) -> List[Finding]:
    """
    Преобразует сырой JSON от Semgrep в список Finding.
    
    Args:
        semgrep_output: dict из semgrep_runner.run_semgrep()
        
    Returns:
        Список Finding (может быть пустым)
    """
    results = semgrep_output.get("results", [])
    findings = []

    for item in results:
        file_path = item.get("path", "unknown")
        line = max(1, int(item.get("start", {}).get("line", 1) or 1))
        rule_id = item.get("check_id", "unknown-rule")
        message = item.get("extra", {}).get("message", "No message")
        finding_type = _parse_type(item, rule_id)
        snippet = _extract_snippet(item, finding_type, rule_id)
        severity = _parse_severity(item)

        findings.append(
            Finding(
                file=file_path,
                line=line,
                rule_id=rule_id,
                type=finding_type,
                severity=severity,
                message=message,
                snippet=snippet,
            )
        )

    return _dedupe_findings(findings)


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    deduped: List[Finding] = []
    seen: set[tuple[str, int, str, str, str]] = set()

    for finding in findings:
        key = (
            str(finding.file).strip(),
            int(finding.line),
            str(finding.rule_id).strip(),
            str(finding.message).strip(),
            str(finding.snippet).strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped


def _extract_snippet(item: dict, finding_type: str, rule_id: str) -> str:
    """Достаёт кусок кода из finding."""
    lines = item.get("extra", {}).get("lines", "")
    if lines and lines.strip().lower() != "requires login":
        return sanitize_snippet(lines, finding_type, rule_id)

    metavars_content = (
        item.get("extra", {}).get("metavars", {}).get("$X", {}).get("abstract_content", "")
    )
    if metavars_content:
        return sanitize_snippet(metavars_content, finding_type, rule_id)

    if is_sensitive_finding(finding_type, rule_id):
        return SENSITIVE_SNIPPET_PLACEHOLDER

    return sanitize_snippet(_read_source_line(item), finding_type, rule_id)


def _parse_severity(item: dict) -> Severity:
    """Конвертирует severity Semgrep → наш Severity enum."""
    raw = item.get("extra", {}).get("severity", "WARNING").upper()
    return _SEVERITY_MAP.get(raw, Severity.MEDIUM)


def _parse_type(item: dict, rule_id: str) -> str:
    metadata = item.get("extra", {}).get("metadata", {})
    candidate = metadata.get("type") or metadata.get("category")
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip().lower()

    if "secret" in rule_id or "password" in rule_id or "key" in rule_id:
        return "secret"

    return "code"


def _read_source_line(item: dict) -> str:
    path = item.get("path")
    line_number = item.get("start", {}).get("line")
    if not path or not line_number:
        return ""

    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""

    index = int(line_number) - 1
    if 0 <= index < len(lines):
        return lines[index].strip()

    return ""
