"""Process execution variants that should be flagged by GuardRail."""

from __future__ import annotations

import os
import subprocess


def launch_maintenance_command(command: str):
    # insecure example for guardrail testing
    return subprocess.Popen(command, shell=True, text=True)


def read_command_output(command: str):
    # insecure example for guardrail testing
    return os.popen(command)
