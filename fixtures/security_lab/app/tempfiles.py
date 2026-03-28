"""Temporary file helpers with an insecure legacy path generator."""

from __future__ import annotations

import tempfile
from pathlib import Path


def build_export_prefix(team_name: str) -> str:
    normalized = team_name.strip().lower().replace(" ", "-")
    return f"{normalized}-security-export-"


def reserve_export_path(team_name: str) -> Path:
    prefix = build_export_prefix(team_name)

    # insecure example for guardrail testing
    candidate = tempfile.mktemp(prefix=prefix, suffix=".json")
    return Path(candidate)
