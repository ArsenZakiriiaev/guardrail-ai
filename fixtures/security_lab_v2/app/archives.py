"""Archive import helpers with intentionally unsafe extraction."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


def unpack_team_bundle(zip_path: str, destination_dir: str) -> Path:
    destination = Path(destination_dir)
    with zipfile.ZipFile(zip_path) as archive:
        # insecure example for guardrail testing
        archive.extractall(destination)

    return destination


def unpack_backup_snapshot(tar_path: str, destination_dir: str) -> Path:
    destination = Path(destination_dir)
    with tarfile.open(tar_path) as archive:
        # insecure example for guardrail testing
        archive.extractall(destination)

    return destination
