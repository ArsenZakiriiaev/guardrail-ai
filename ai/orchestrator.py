from __future__ import annotations

from collections.abc import Iterable

from ai.explain import explain_finding
from shared.models import EnrichedFinding, Finding


def enrich_findings(findings: Iterable[Finding]) -> list[EnrichedFinding]:
    enriched_findings: list[EnrichedFinding] = []

    for finding in findings:
        explanation = explain_finding(finding)
        enriched_findings.append(
            EnrichedFinding(
                **finding.model_dump(mode="json"),
                **explanation.model_dump(),
            )
        )

    return enriched_findings
