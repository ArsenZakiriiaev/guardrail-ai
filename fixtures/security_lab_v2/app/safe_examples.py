"""Safe reference implementations for selected V2 scenarios."""

from __future__ import annotations

import os
import re
import tarfile
import tempfile
import zipfile
from pathlib import Path


def safe_join_data_path(base_dir: str, relative_name: str) -> Path:
    candidate = (Path(base_dir) / relative_name).resolve()
    root = Path(base_dir).resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError("path escapes base directory")
    return candidate


def safe_tempfile() -> str:
    handle = tempfile.NamedTemporaryFile(prefix="guardrail-", suffix=".lock", delete=False)
    path = handle.name
    handle.close()
    return path


def safe_permissions(path: str) -> None:
    os.chmod(path, 0o750)


def safe_regex_search(literal_fragment: str, text: str):
    escaped = re.escape(literal_fragment)
    return re.search(escaped, text)


def safe_zip_members(zip_path: str) -> list[str]:
    with zipfile.ZipFile(zip_path) as archive:
        return archive.namelist()


def safe_tar_members(tar_path: str) -> list[str]:
    with tarfile.open(tar_path) as archive:
        return archive.getnames()
