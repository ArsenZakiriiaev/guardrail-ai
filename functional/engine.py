"""
functional/engine.py

Orchestrates a full functional test run:
  1. Extract use cases from a PDF spec using Claude
  2. Execute each use case against a live HTTP base URL
  3. Ask Claude whether each response satisfies the expectations
  4. Return a FunctionalTestReport (optionally rendered to HTML)
"""
from __future__ import annotations

from pathlib import Path

from functional import claude_client
from functional.models import FunctionalTestReport, FunctionalTestResult, UseCase
from functional.reporter import render_html_report
from functional.runner import execute


def run_functional_tests(
    pdf_path: str | Path,
    base_url: str,
    *,
    auth_header: str | None = None,
    api_key: str | None = None,
    timeout_seconds: float = 10.0,
    html_report_path: str | Path | None = None,
) -> FunctionalTestReport:
    """
    Run all use cases described in *pdf_path* against *base_url*.

    Parameters
    ----------
    pdf_path:
        Path to a PDF document describing HTTP API use cases / test scenarios.
    base_url:
        Scheme + host (+ optional port) of the running target application,
        e.g. ``http://localhost:8000``.
    auth_header:
        Optional single auth header in ``"Name: value"`` format,
        e.g. ``"Authorization: Bearer mytoken"``.
    api_key:
        Anthropic API key.  Falls back to ``ANTHROPIC_API_KEY`` env var.
    timeout_seconds:
        Per-request HTTP timeout.
    html_report_path:
        If provided, write a standalone HTML report to this path.
    """
    pdf_path = Path(pdf_path)
    auth_headers = _parse_auth_header(auth_header)

    # ── 1. Extract use cases from PDF ────────────────────────────────────────
    raw_cases = claude_client.extract_use_cases(pdf_path, api_key=api_key)
    use_cases = [_coerce_use_case(raw) for raw in raw_cases]

    # ── 2. Execute each use case and analyse the response ────────────────────
    results: list[FunctionalTestResult] = []
    for uc in use_cases:
        result = _run_single(uc, base_url, auth_headers, timeout_seconds, api_key)
        results.append(result)

    # ── 3. Tally ─────────────────────────────────────────────────────────────
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    errors = sum(1 for r in results if r.status == "error")

    report = FunctionalTestReport(
        pdf_path=str(pdf_path),
        target=base_url,
        total=len(results),
        passed=passed,
        failed=failed,
        errors=errors,
        use_cases=use_cases,
        results=results,
    )

    if html_report_path:
        html_path = Path(html_report_path)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html_report(report), encoding="utf-8")
        report.html_report_path = str(html_path)

    return report


# ── private helpers ───────────────────────────────────────────────────────────

def _run_single(
    use_case: UseCase,
    base_url: str,
    auth_headers: dict[str, str],
    timeout_seconds: float,
    api_key: str | None,
) -> FunctionalTestResult:
    http = execute(use_case, base_url, auth_headers=auth_headers, timeout_seconds=timeout_seconds)

    if http.error:
        return FunctionalTestResult(
            use_case=use_case,
            passed=False,
            status="error",
            failure_reason=http.error,
            analysis=f"HTTP request failed: {http.error}",
        )

    verdict = claude_client.analyze_result(
        use_case.model_dump(),
        actual_status=http.status_code,
        actual_body=http.body,
        api_key=api_key,
    )

    passed = bool(verdict.get("passed", False))
    return FunctionalTestResult(
        use_case=use_case,
        passed=passed,
        status="pass" if passed else "fail",
        actual_status_code=http.status_code,
        actual_response_body=http.body[:4000],
        analysis=verdict.get("analysis", ""),
        failure_reason=verdict.get("failure_reason"),
    )


def _coerce_use_case(raw: dict) -> UseCase:
    """Safely convert a raw dict from Claude into a UseCase, filling defaults."""
    return UseCase(
        name=str(raw.get("name", "Unnamed")),
        description=str(raw.get("description", "")),
        endpoint=str(raw.get("endpoint", "/")),
        method=str(raw.get("method", "GET")),
        request_body=raw.get("request_body") or {},
        request_params={str(k): str(v) for k, v in (raw.get("request_params") or {}).items()},
        request_headers={str(k): str(v) for k, v in (raw.get("request_headers") or {}).items()},
        expected_status=raw.get("expected_status"),
        expected_behavior=str(raw.get("expected_behavior", "")),
    )


def _parse_auth_header(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    if ":" not in raw:
        raise ValueError("Auth header must be in 'Name: value' format.")
    key, value = raw.split(":", 1)
    return {key.strip(): value.strip()}
