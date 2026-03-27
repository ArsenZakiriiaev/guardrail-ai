"""
scanner/parser.py — парсит JSON-ответ Semgrep в список Finding.
"""

from typing import List
from shared.models import Finding, Severity


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
        # Достаём нужные поля из Semgrep JSON
        file_path = item.get("path", "unknown")
        line = item.get("start", {}).get("line", 0)
        rule_id = item.get("check_id", "unknown-rule")
        message = item.get("extra", {}).get("message", "No message")
        snippet = _extract_snippet(item)
        severity = _parse_severity(item)

        findings.append(Finding(
            file=file_path,
            line=line,
            rule_id=rule_id,
            message=message,
            snippet=snippet,
            severity=severity,
        ))

    return findings


def _extract_snippet(item: dict) -> str:
    """Достаёт кусок кода из finding."""
    lines = item.get("extra", {}).get("lines", "")
    if lines:
        return lines.strip()
    
    # Fallback: берём из метаданных если есть
    return item.get("extra", {}).get("metavars", {}).get("$X", {}).get("abstract_content", "")


def _parse_severity(item: dict) -> Severity:
    """Конвертирует severity Semgrep → наш Severity enum."""
    raw = item.get("extra", {}).get("severity", "WARNING").upper()
    return _SEVERITY_MAP.get(raw, Severity.MEDIUM)
