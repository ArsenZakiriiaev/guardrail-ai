"""
web/app.py — FastAPI web-приложение для Guardrail AI.
Принимает один файл, несколько файлов или ZIP-архив с проектом.
Сканирует Semgrep-ом, возвращает результаты с AI-объяснениями.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import requests

from pentest.api import (
    MAX_TOTAL_SIZE,
    extract_safe_zip,
    materialize_files,
    normalize_code_payload,
    run_pentest_from_files,
    run_pentest_from_url,
    run_pentest_from_zip,
    validate_total_size,
)
from scanner.semgrep_runner import run_semgrep
from scanner.parser import parse_findings
from shared.redaction import sanitize_snippet
from ai.explain import explain_finding
from ai.fix import fix_finding
from ai.second_pass import key_for_finding, run_claude_second_pass

app = FastAPI(title="Guardrail AI", version="0.3.0")

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC_DIR / "index.html").read_text()


def _scan_directory(scan_dir: Path, *, claude_api_key: str | None = None) -> tuple[list[dict], dict]:
    """Scan all Python files in a directory, return enriched findings."""
    try:
        raw = run_semgrep(str(scan_dir))
        findings = parse_findings(raw)
    except Exception as e:
        return [{"error": str(e)}], {}

    results = []
    items_by_key: dict[tuple[str, int, str], dict] = {}
    for f in findings:
        # Make file path relative to scan dir
        try:
            rel_file = str(Path(f.file).relative_to(scan_dir))
        except ValueError:
            rel_file = f.file

        snippet = sanitize_snippet(f.snippet, f.type, f.rule_id)

        item = {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "message": f.message,
            "line": f.line,
            "file": rel_file,
            "snippet": snippet,
            "explanation": None,
            "fix": None,
        }

        try:
            explanation = explain_finding(f, api_key=claude_api_key)
            item["explanation"] = {
                "summary": explanation.summary,
                "risk": explanation.risk,
                "fix": explanation.fix,
            }
        except Exception:
            pass

        try:
            fix = fix_finding(f, api_key=claude_api_key)
            item["fix"] = {
                "fixed_code": fix.fixed_code,
                "explanation": fix.explanation,
            }
        except Exception:
            pass

        results.append(item)
        items_by_key[key_for_finding(f)] = item

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda r: severity_order.get(r["severity"], 99))

    claude_reviews, claude_metadata = run_claude_second_pass(findings, api_key=claude_api_key)
    for finding in findings:
        review = claude_reviews.get(key_for_finding(finding))
        if review:
            items_by_key[key_for_finding(finding)]["claude_explanation"] = _serialize_explanation(review)

    metadata: dict[str, object] = {}
    if claude_metadata.get("requested"):
        metadata["claude_second_pass"] = claude_metadata

    return results, metadata


def _build_response(results: list[dict], metadata: dict | None = None) -> JSONResponse:
    blocked = sum(1 for r in results if r.get("severity") in ("high", "critical"))
    warned = sum(1 for r in results if r.get("severity") == "medium")
    # Collect unique files
    files = sorted(set(r.get("file", "unknown") for r in results))
    payload = {
        "findings": results,
        "summary": {
            "total": len(results),
            "blocked": blocked,
            "warned": warned,
            "files_scanned": len(files),
            "files_with_issues": files,
        },
    }
    if metadata:
        payload["metadata"] = metadata
    return JSONResponse(payload)


@app.post("/api/scan")
async def scan_code(request: Request):
    """Scan one or multiple files passed as JSON: { files: { "name.py": "code..." } }"""
    body = await request.json()

    # Backwards compat: single-file mode
    files = normalize_code_payload(body)

    if not files:
        return JSONResponse({"findings": [], "summary": {"total": 0}})

    try:
        validate_total_size(files)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    scan_dir = Path(tempfile.mkdtemp(prefix="guardrail_"))
    try:
        materialize_files(scan_dir, files)
        results, metadata = _scan_directory(
            scan_dir,
            claude_api_key=body.get("claude_api_key"),
        )
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)

    return _build_response(results, metadata)


@app.post("/api/scan-zip")
async def scan_zip(file: UploadFile = File(...), claude_api_key: str | None = Form(None)):
    """Upload a .zip of a Python project for scanning."""
    if not file.filename or not file.filename.endswith(".zip"):
        return JSONResponse({"error": "Please upload a .zip file."}, status_code=400)

    data = await file.read()
    if len(data) > MAX_TOTAL_SIZE * 5:
        return JSONResponse({"error": "ZIP too large (max 10MB)."}, status_code=400)

    scan_dir = Path(tempfile.mkdtemp(prefix="guardrail_zip_"))
    try:
        extract_safe_zip(data, scan_dir)
        results, metadata = _scan_directory(scan_dir, claude_api_key=claude_api_key)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)

    return _build_response(results, metadata)


@app.post("/api/pentest")
async def pentest_code(request: Request):
    body = await request.json()
    try:
        if _runner_url():
            payload = _proxy_pentest_json(body)
        else:
            payload = run_pentest_from_files(
                normalize_code_payload(body),
                auth_header=body.get("auth_header"),
                ai=bool(body.get("ai", False)),
                claude_api_key=body.get("claude_api_key"),
            )
        return JSONResponse(payload)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/pentest-zip")
async def pentest_zip(
    file: UploadFile = File(...),
    auth_header: str | None = Form(None),
    ai: bool = Form(False),
    claude_api_key: str | None = Form(None),
):
    if not file.filename or not file.filename.endswith(".zip"):
        return JSONResponse({"error": "Please upload a .zip file."}, status_code=400)

    data = await file.read()
    try:
        if _runner_url():
            payload = _proxy_pentest_zip(
                data,
                file.filename,
                auth_header=auth_header,
                ai=ai,
                claude_api_key=claude_api_key,
            )
        else:
            payload = run_pentest_from_zip(
                data,
                auth_header=auth_header,
                ai=ai,
                claude_api_key=claude_api_key,
            )
        return JSONResponse(payload)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/pentest-url")
async def pentest_url(request: Request):
    body = await request.json()
    try:
        if _runner_url():
            payload = _proxy_pentest_url(body)
        else:
            payload = run_pentest_from_url(
                body.get("url", ""),
                auth_header=body.get("auth_header"),
                ai=bool(body.get("ai", False)),
                claude_api_key=body.get("claude_api_key"),
                active=bool(body.get("active", False)),
            )
        return JSONResponse(payload)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/functional")
async def functional_tests(
    file: UploadFile = File(...),
    target_url: str = Form(...),
    auth_header: str | None = Form(None),
    api_key: str | None = Form(None),
):
    """Upload a PDF spec, extract use cases with Claude, run them against target_url."""
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        return JSONResponse({"error": "Please upload a PDF file."}, status_code=400)

    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        return JSONResponse({"error": "PDF too large (max 20 MB)."}, status_code=400)

    tmp_path = None
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        from functional.engine import run_functional_tests
        report = run_functional_tests(
            pdf_path=tmp_path,
            base_url=target_url.strip(),
            auth_header=auth_header or None,
            api_key=api_key or None,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return JSONResponse({
        "mode": "functional",
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "errors": report.errors,
        "results": [
            {
                "name": r.use_case.name,
                "description": r.use_case.description,
                "endpoint": r.use_case.endpoint,
                "method": r.use_case.method,
                "expected_status": r.use_case.expected_status,
                "expected_behavior": r.use_case.expected_behavior,
                "status": r.status,
                "passed": r.passed,
                "actual_status_code": r.actual_status_code,
                "analysis": r.analysis,
                "failure_reason": r.failure_reason,
            }
            for r in report.results
        ],
    })


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.3.0"}


def _runner_url() -> str:
    return os.getenv("GUARDRAIL_PENTEST_RUNNER_URL", "").strip().rstrip("/")


def _runner_headers() -> dict[str, str]:
    headers = {}
    token = os.getenv("GUARDRAIL_PENTEST_RUNNER_TOKEN", "").strip()
    if token:
        headers["X-Guardrail-Runner-Token"] = token
    return headers


def _proxy_pentest_json(body: dict) -> dict:
    response = requests.post(
        f"{_runner_url()}/api/pentest",
        json=body,
        headers=_runner_headers(),
        timeout=float(os.getenv("GUARDRAIL_PENTEST_RUNNER_TIMEOUT", "180")),
    )
    return _parse_runner_response(response)


def _proxy_pentest_zip(
    data: bytes,
    filename: str,
    *,
    auth_header: str | None,
    ai: bool,
    claude_api_key: str | None = None,
) -> dict:
    response = requests.post(
        f"{_runner_url()}/api/pentest-zip",
        data={"auth_header": auth_header or "", "ai": str(ai).lower(), "claude_api_key": claude_api_key or ""},
        files={"file": (filename, data, "application/zip")},
        headers=_runner_headers(),
        timeout=float(os.getenv("GUARDRAIL_PENTEST_RUNNER_TIMEOUT", "180")),
    )
    return _parse_runner_response(response)


def _proxy_pentest_url(body: dict) -> dict:
    response = requests.post(
        f"{_runner_url()}/api/pentest-url",
        json=body,
        headers=_runner_headers(),
        timeout=float(os.getenv("GUARDRAIL_PENTEST_RUNNER_TIMEOUT", "180")),
    )
    return _parse_runner_response(response)


def _parse_runner_response(response: requests.Response) -> dict:
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(f"Pentest runner returned invalid JSON (HTTP {response.status_code}).") from exc

    if response.ok:
        return payload

    detail = payload.get("detail") or payload.get("error") or f"Pentest runner HTTP {response.status_code}"
    raise RuntimeError(str(detail))


def _serialize_explanation(explanation) -> dict[str, str]:
    return {
        "summary": getattr(explanation, "summary", ""),
        "risk": getattr(explanation, "risk", ""),
        "fix": getattr(explanation, "fix", ""),
    }
