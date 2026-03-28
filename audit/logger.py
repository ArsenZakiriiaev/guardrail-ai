"""
audit/logger.py — аудит-лог всех действий guardrail.
Записывает находки, решения политики, блокировки в JSON-файл.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.models import Finding
from shared.redaction import sanitize_snippet


AUDIT_DIR_NAME = ".guardrail"
AUDIT_FILE_NAME = "audit.jsonl"


def _get_audit_path(project_root: str | Path) -> Path:
    audit_dir = Path(project_root) / AUDIT_DIR_NAME
    audit_dir.mkdir(exist_ok=True)

    gitignore = audit_dir / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*\n")

    return audit_dir / AUDIT_FILE_NAME


def log_event(
    project_root: str | Path,
    event_type: str,
    *,
    findings: list[Finding] | None = None,
    blocked: int = 0,
    warned: int = 0,
    ignored: int = 0,
    trigger: str = "",
    target: str = "",
    details: str = "",
) -> None:
    """
    Записывает событие аудита в JSONL-файл.

    event_type: scan | watch_alert | pre_commit | pre_push | policy_init | hook_install
    trigger: что вызвало событие (file_change, git_commit, manual, etc.)
    """
    audit_path = _get_audit_path(project_root)

    safe_findings = []
    for f in (findings or []):
        safe_findings.append({
            "rule_id": f.rule_id,
            "type": f.type,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "snippet": sanitize_snippet(f.snippet, f.type, f.rule_id),
        })

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "trigger": trigger,
        "target": target,
        "summary": {
            "total": len(safe_findings),
            "blocked": blocked,
            "warned": warned,
            "ignored": ignored,
        },
        "findings": safe_findings,
        "details": details,
    }

    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_audit_log(
    project_root: str | Path,
    limit: int = 50,
    event_filter: str | None = None,
) -> list[dict]:
    """
    Читает последние N записей из аудит-лога.
    """
    audit_path = _get_audit_path(project_root)
    if not audit_path.exists():
        return []

    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()

    entries = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event_filter and entry.get("event") != event_filter:
            continue

        entries.append(entry)
        if len(entries) >= limit:
            break

    return entries
