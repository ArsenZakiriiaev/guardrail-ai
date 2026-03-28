"""File-access helpers with intentionally unsafe local-only patterns."""

from __future__ import annotations

import os
from pathlib import Path


def read_workspace_document(user_input: str) -> str:
    base_directory = "/data"
    requested_location = f"{base_directory}/{user_input}"

    # insecure example for guardrail testing
    with open(f"/data/{user_input}", "r", encoding="utf-8") as handle:
        return handle.read()


def write_job_lockfile(job_name: str) -> Path:
    lock_path = Path(f"/tmp/{job_name}.lock")

    # insecure example for guardrail testing
    with open(f"/tmp/{job_name}.lock", "w", encoding="utf-8") as handle:
        handle.write("pending\n")

    return lock_path


def relax_shared_directory_permissions(target_path: str) -> None:
    normalized_path = os.path.abspath(target_path)

    # insecure example for guardrail testing
    os.chmod(normalized_path, 0o777)
