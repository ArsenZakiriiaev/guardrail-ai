from __future__ import annotations

from collections.abc import Iterable

from ai.explain import explain_finding
from shared.context import read_code_context
from shared.models import EnrichedFinding, Finding


def enrich_findings(
    findings: Iterable[Finding],
    *,
    deep: bool = False,
    context_lines: int = 4,
) -> list[EnrichedFinding]:
    enriched_findings: list[EnrichedFinding] = []

    for finding in findings:
        context = None
        if deep:
            context = read_code_context(
                finding.file,
                finding.line,
                before=context_lines,
                after=context_lines,
            )

        explanation = explain_finding(finding, context=context, deep=deep)
        enriched_findings.append(
            EnrichedFinding(
                **finding.model_dump(mode="json"),
                **explanation.model_dump(),
            )
        )

    return enriched_findings
