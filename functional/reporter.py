"""
functional/reporter.py — generates a self-contained HTML report for a FunctionalTestReport.
"""
from __future__ import annotations

import html
from datetime import datetime

from functional.models import FunctionalTestReport, FunctionalTestResult


def render_html_report(report: FunctionalTestReport) -> str:
    pass_pct = round(report.passed / report.total * 100) if report.total else 0
    verdict_color = "#22c55e" if report.failed == 0 and report.errors == 0 else "#ef4444"
    verdict_label = "PASS" if report.failed == 0 and report.errors == 0 else "FAIL"

    rows = "\n".join(_result_row(i, r) for i, r in enumerate(report.results))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Functional Test Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #0f172a; color: #e2e8f0; line-height: 1.5; padding: 2rem; }}
  h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: .25rem; }}
  .meta {{ color: #94a3b8; font-size: .85rem; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: #1e293b; border-radius: .5rem; padding: 1rem 1.5rem; min-width: 110px; }}
  .card .label {{ font-size: .75rem; text-transform: uppercase; color: #64748b; }}
  .card .value {{ font-size: 1.75rem; font-weight: 700; }}
  .pass  {{ color: #22c55e; }} .fail {{ color: #ef4444; }} .err {{ color: #f59e0b; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; font-size: .75rem; text-transform: uppercase; color: #64748b;
        padding: .5rem .75rem; border-bottom: 1px solid #334155; }}
  td {{ padding: .6rem .75rem; border-bottom: 1px solid #1e293b; vertical-align: top; font-size: .875rem; }}
  tr:hover td {{ background: #1e293b; }}
  .badge {{ display: inline-block; border-radius: 9999px; padding: .15rem .55rem;
            font-size: .75rem; font-weight: 600; text-transform: uppercase; }}
  .badge-pass {{ background: #14532d; color: #86efac; }}
  .badge-fail {{ background: #450a0a; color: #fca5a5; }}
  .badge-error {{ background: #451a03; color: #fcd34d; }}
  details summary {{ cursor: pointer; color: #94a3b8; font-size: .8rem; margin-top: .25rem; }}
  pre {{ background: #0f172a; border-radius: .25rem; padding: .5rem; font-size: .75rem;
         overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin-top: .25rem; }}
  .verdict {{ font-size: 1.1rem; font-weight: 700; color: {verdict_color}; }}
</style>
</head>
<body>
<h1>Functional Test Report</h1>
<p class="meta">
  Target: <strong>{html.escape(report.target)}</strong> &nbsp;|&nbsp;
  Spec: <strong>{html.escape(report.pdf_path)}</strong> &nbsp;|&nbsp;
  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}
  &nbsp;|&nbsp; <span class="verdict">{verdict_label}</span>
</p>

<div class="summary">
  <div class="card"><div class="label">Total</div><div class="value">{report.total}</div></div>
  <div class="card"><div class="label">Passed</div><div class="value pass">{report.passed}</div></div>
  <div class="card"><div class="label">Failed</div><div class="value fail">{report.failed}</div></div>
  <div class="card"><div class="label">Errors</div><div class="value err">{report.errors}</div></div>
  <div class="card"><div class="label">Pass Rate</div><div class="value">{pass_pct}%</div></div>
</div>

<table>
  <thead>
    <tr>
      <th>#</th><th>Use Case</th><th>Endpoint</th>
      <th>Expected</th><th>Actual</th><th>Result</th><th>Analysis</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
</body>
</html>"""


def _result_row(idx: int, result: FunctionalTestResult) -> str:
    uc = result.use_case
    badge = {
        "pass":  '<span class="badge badge-pass">pass</span>',
        "fail":  '<span class="badge badge-fail">fail</span>',
        "error": '<span class="badge badge-error">error</span>',
    }.get(result.status, '<span class="badge badge-error">error</span>')

    expected = f"{uc.expected_status}" if uc.expected_status else "—"
    actual = str(result.actual_status_code) if result.actual_status_code is not None else "—"

    body_preview = ""
    if result.actual_response_body:
        snippet = html.escape(result.actual_response_body[:500])
        body_preview = f"<details><summary>response body</summary><pre>{snippet}</pre></details>"

    failure_note = ""
    if result.failure_reason:
        failure_note = f"<br><small style='color:#f87171'>{html.escape(result.failure_reason)}</small>"

    return (
        f"    <tr>"
        f"<td>{idx + 1}</td>"
        f"<td><strong>{html.escape(uc.name)}</strong>"
        f"<br><small style='color:#94a3b8'>{html.escape(uc.description[:120])}</small></td>"
        f"<td><code>{html.escape(uc.method)} {html.escape(uc.endpoint)}</code></td>"
        f"<td>{expected}</td>"
        f"<td>{actual}</td>"
        f"<td>{badge}</td>"
        f"<td>{html.escape(result.analysis)}{failure_note}{body_preview}</td>"
        f"</tr>"
    )
