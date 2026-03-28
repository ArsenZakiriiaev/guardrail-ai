"""
web/app.py — FastAPI web-приложение для Guardrail AI.
Принимает один файл, несколько файлов или ZIP-архив с проектом.
Сканирует Semgrep-ом, возвращает результаты с AI-объяснениями.
"""

from __future__ import annotations

import io
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from pentest.engine import run_pentest
from scanner.semgrep_runner import run_semgrep
from scanner.parser import parse_findings
from shared.redaction import sanitize_snippet
from ai.explain import explain_finding
from ai.fix import fix_finding

app = FastAPI(title="Guardrail AI", version="0.3.0")

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

MAX_TOTAL_SIZE = 2_000_000  # 2 MB total upload limit


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC_DIR / "index.html").read_text()


def _scan_directory(scan_dir: Path) -> list[dict]:
    """Scan all Python files in a directory, return enriched findings."""
    try:
        raw = run_semgrep(str(scan_dir))
        findings = parse_findings(raw)
    except Exception as e:
        return [{"error": str(e)}]

    results = []
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

    return results


def _build_response(results: list[dict]) -> JSONResponse:
    blocked = sum(1 for r in results if r.get("severity") in ("high", "critical"))
    warned = sum(1 for r in results if r.get("severity") == "medium")
    # Collect unique files
    files = sorted(set(r.get("file", "unknown") for r in results))
    return JSONResponse({
        "findings": results,
        "summary": {
            "total": len(results),
            "blocked": blocked,
            "warned": warned,
            "files_scanned": len(files),
            "files_with_issues": files,
        },
    })


def _build_pentest_response(report) -> JSONResponse:
    findings = []
    for finding in report.findings:
        explanation = None
        if finding.explanation:
            explanation = {
                "summary": getattr(finding.explanation, "summary", ""),
                "risk": getattr(finding.explanation, "risk", ""),
                "fix": getattr(finding.explanation, "fix", ""),
            }

        findings.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "message": finding.message,
                "line": finding.line,
                "file": finding.file,
                "endpoint": finding.endpoint,
                "method": finding.method,
                "snippet": finding.snippet,
                "evidence": finding.evidence,
                "proof": finding.proof,
                "policy_action": finding.policy_action,
                "explanation": explanation,
            }
        )

    return JSONResponse(
        {
            "mode": "pentest",
            "framework": report.framework,
            "target": report.target,
            "findings": findings,
            "summary": report.summary.model_dump(mode="json"),
            "endpoints": [endpoint.model_dump(mode="json") for endpoint in report.endpoints],
        }
    )


def _materialize_files(scan_dir: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        safe_path = Path(name)
        if safe_path.is_absolute() or ".." in safe_path.parts:
            continue

        if safe_path.suffix != ".py":
            if safe_path.name not in {"requirements.txt", "pyproject.toml"}:
                continue

        target = scan_dir / safe_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


@app.post("/api/scan")
async def scan_code(request: Request):
    """Scan one or multiple files passed as JSON: { files: { "name.py": "code..." } }"""
    body = await request.json()

    # Backwards compat: single-file mode
    code = body.get("code", "")
    files = body.get("files", {})

    if code and not files:
        files = {"main.py": code}

    if not files:
        return JSONResponse({"findings": [], "summary": {"total": 0}})

    total_size = sum(len(v) for v in files.values())
    if total_size > MAX_TOTAL_SIZE:
        return JSONResponse({"error": f"Total code size {total_size} exceeds limit ({MAX_TOTAL_SIZE})."}, status_code=400)

    scan_dir = Path(tempfile.mkdtemp(prefix="guardrail_"))
    try:
        _materialize_files(scan_dir, files)
        results = _scan_directory(scan_dir)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)

    return _build_response(results)


@app.post("/api/scan-zip")
async def scan_zip(file: UploadFile = File(...)):
    """Upload a .zip of a Python project for scanning."""
    if not file.filename or not file.filename.endswith(".zip"):
        return JSONResponse({"error": "Please upload a .zip file."}, status_code=400)

    data = await file.read()
    if len(data) > MAX_TOTAL_SIZE * 5:
        return JSONResponse({"error": "ZIP too large (max 10MB)."}, status_code=400)

    scan_dir = Path(tempfile.mkdtemp(prefix="guardrail_zip_"))
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            # Filter: only extract .py files, skip hidden/venv
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                # Skip dangerous paths
                if ".." in name or name.startswith("/"):
                    continue
                # Skip non-python
                if not name.endswith(".py"):
                    continue
                # Skip venv, node_modules, etc
                parts = Path(name).parts
                skip_dirs = {".venv", "venv", "node_modules", "__pycache__", ".git", "env", ".tox"}
                if any(p in skip_dirs for p in parts):
                    continue
                # Extract safely
                target = scan_dir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(info.filename))

        results = _scan_directory(scan_dir)
    except zipfile.BadZipFile:
        return JSONResponse({"error": "Invalid ZIP file."}, status_code=400)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)

    return _build_response(results)


@app.post("/api/pentest")
async def pentest_code(request: Request):
    body = await request.json()
    code = body.get("code", "")
    files = body.get("files", {})
    auth_header = body.get("auth_header")
    ai = bool(body.get("ai", False))

    if code and not files:
        files = {"main.py": code}

    if not files:
        return JSONResponse({"error": "No files supplied for pentest."}, status_code=400)

    total_size = sum(len(v) for v in files.values())
    if total_size > MAX_TOTAL_SIZE:
        return JSONResponse({"error": f"Total code size {total_size} exceeds limit ({MAX_TOTAL_SIZE})."}, status_code=400)

    scan_dir = Path(tempfile.mkdtemp(prefix="guardrail_pentest_"))
    try:
        _materialize_files(scan_dir, files)
        report = run_pentest(scan_dir, auth_header=auth_header, enable_ai=ai)
        return _build_pentest_response(report)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


@app.post("/api/pentest-zip")
async def pentest_zip(file: UploadFile = File(...), auth_header: str | None = None, ai: bool = False):
    if not file.filename or not file.filename.endswith(".zip"):
        return JSONResponse({"error": "Please upload a .zip file."}, status_code=400)

    data = await file.read()
    if len(data) > MAX_TOTAL_SIZE * 5:
        return JSONResponse({"error": "ZIP too large (max 10MB)."}, status_code=400)

    scan_dir = Path(tempfile.mkdtemp(prefix="guardrail_pentest_zip_"))
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if ".." in name or name.startswith("/"):
                    continue
                parts = Path(name).parts
                skip_dirs = {".venv", "venv", "node_modules", "__pycache__", ".git", "env", ".tox"}
                if any(p in skip_dirs for p in parts):
                    continue
                target = scan_dir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(info.filename))

        report = run_pentest(scan_dir, auth_header=auth_header, enable_ai=ai)
        return _build_pentest_response(report)
    except zipfile.BadZipFile:
        return JSONResponse({"error": "Invalid ZIP file."}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.3.0"}
