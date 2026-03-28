"""Local maintenance helpers that intentionally contain unsafe process APIs."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class MaintenanceTask:
    name: str
    command: str
    execute: bool = False


def plan_cache_refresh(cache_name: str) -> MaintenanceTask:
    command = f"echo refreshing {cache_name}"
    return MaintenanceTask(name="refresh-cache", command=command, execute=False)


def run_shell_task(task: MaintenanceTask) -> subprocess.CompletedProcess[str] | None:
    """Do not enable execute in normal fixture usage."""
    if not task.execute:
        return None

    # insecure example for guardrail testing
    return subprocess.run(task.command, shell=True, text=True, capture_output=True)


def run_legacy_system_task(task: MaintenanceTask) -> int | None:
    if not task.execute:
        return None

    # insecure example for guardrail testing
    return os.system(task.command)
