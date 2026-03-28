from __future__ import annotations

from collections.abc import Iterable

from ai.claude import explain_finding_with_claude
from shared.models import ExplanationResult, Finding


def key_for_finding(finding: Finding) -> tuple[str, int, str]:
    return (finding.file, finding.line, finding.rule_id)


def run_claude_second_pass(
    findings: Iterable[Finding],
    *,
    api_key: str | None = None,
) -> tuple[dict[tuple[str, int, str], ExplanationResult], dict[str, object]]:
    normalized_key = (api_key or "").strip()
    metadata: dict[str, object] = {
        "requested": bool(normalized_key),
        "completed": 0,
        "failed": 0,
    }
    if not normalized_key:
        return {}, metadata

    explanations: dict[tuple[str, int, str], ExplanationResult] = {}
    first_error: str | None = None

    for finding in findings:
        try:
            explanations[key_for_finding(finding)] = explain_finding_with_claude(
                finding,
                api_key=normalized_key,
                independent=True,
            )
            metadata["completed"] = int(metadata["completed"]) + 1
        except Exception as exc:
            metadata["failed"] = int(metadata["failed"]) + 1
            if first_error is None:
                first_error = str(exc)

    if first_error:
        metadata["error"] = first_error

    return explanations, metadata
