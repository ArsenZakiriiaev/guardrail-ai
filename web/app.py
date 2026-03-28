"""
web/app.py — FastAPI web-приложение для Guardrail AI.
Принимает Python-код, сканирует Semgrep-ом, возвращает результаты с AI-объяснениями.
"""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from scanner.semgrep_runner import run_semgrep
from scanner.parser import parse_findings
from shared.redaction import sanitize_snippet
from ai.explain import explain_finding
from ai.fix import fix_finding

app = FastAPI(title="Guardrail AI", version="0.2.0")

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC_DIR / "index.html").read_text()


@app.post("/api/scan")
async def scan_code(request: Request):
    body = await request.json()
    code: str = body.get("code", "")

    if not code.strip():
        return JSONResponse({"findings": [], "summary": "No code provided."})

    if len(code) > 100_000:
        return JSONResponse(
            {"error": "Code too large (max 100KB)."},
            status_code=400,
        )

    # Write to temp file for semgrep
    scan_id = uuid.uuid4().hex[:8]
    tmp_dir = Path(tempfile.mkdtemp(prefix="guardrail_"))
    tmp_file = tmp_dir / f"scan_{scan_id}.py"

    try:
        tmp_file.write_text(code)
        raw = run_semgrep(str(tmp_file))
        findings = parse_findings(raw)
    except Exception as e:
        return JSONResponse(
            {"error": f"Scan failed: {str(e)}"},
            status_code=500,
        )
    finally:
        tmp_file.unlink(missing_ok=True)
        tmp_dir.rmdir()

    results = []
    for f in findings:
        snippet = sanitize_snippet(f.snippet, f.type, f.rule_id)

        item = {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "message": f.message,
            "line": f.line,
            "snippet": snippet,
            "explanation": None,
            "fix": None,
        }

        try:
            explanation = explain_finding(f)
            item["explanation"] = {
                "summary": explanation.summary,
                "risk": explanation.risk,
                "fix": explanation.fix,
            }
        except Exception:
            pass

        try:
            fix = fix_finding(f)
            item["fix"] = {
                "fixed_code": fix.fixed_code,
                "explanation": fix.explanation,
            }
        except Exception:
            pass

        results.append(item)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda r: severity_order.get(r["severity"], 99))

    blocked = sum(1 for r in results if r["severity"] in ("high", "critical"))
    warned = sum(1 for r in results if r["severity"] == "medium")

    return JSONResponse({
        "findings": results,
        "summary": {
            "total": len(results),
            "blocked": blocked,
            "warned": warned,
        },
    })


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}
