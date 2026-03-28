"""
ai/orchestrator.py — STUB для Dev 2.
Dev 1 заменит этот файл своей реализацией.
До тех пор CLI работает без AI-обогащения.
"""

from typing import List
from shared.models import Finding, EnrichedFinding


def enrich_findings(findings: List[Finding]) -> List[EnrichedFinding]:
    """
    STUB: просто оборачивает Finding в EnrichedFinding без AI.
    Dev 1 заменит эту реализацию на вызов explain/fix.
    """
    result = []
    for f in findings:
        result.append(EnrichedFinding(
            file=f.file,
            line=f.line,
            rule_id=f.rule_id,
            message=f.message,
            snippet=f.snippet,
            severity=f.severity,
            explanation=None,       # Dev 1 заполнит
            fix_available=False,    # Dev 1 заполнит
            fixed_code=None,        # Dev 1 заполнит
        ))
    return result
