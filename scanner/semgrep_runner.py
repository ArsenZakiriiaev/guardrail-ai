"""
scanner/semgrep_runner.py — запускает Semgrep через subprocess,
возвращает сырой JSON с результатами.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from scanner.heuristics import analyze_python_heuristics


# Папка с правилами относительно корня проекта
RULES_DIR = Path(__file__).parent.parent / "rules"


def run_semgrep(target: str) -> dict:
    """
    Запускает Semgrep на файл или папку.
    
    Args:
        target: путь к файлу или директории
        
    Returns:
        dict с полями 'results' и 'errors' из Semgrep JSON output
        
    Raises:
        FileNotFoundError: если Semgrep не установлен
        ValueError: если target не существует
    """
    target_path = Path(target)
    if not target_path.exists():
        raise ValueError(f"Target does not exist: {target}")

    semgrep_bin = _resolve_semgrep_binary()
    cmd = [
        semgrep_bin,
        "scan",
        "--config", str(RULES_DIR),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        str(target_path),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=_build_semgrep_env(),
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "Semgrep not found. Install it: pip install semgrep"
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Semgrep timed out scanning: {target}")

    # Semgrep exits with code 1 when findings exist — это нормально
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep failed (exit {result.returncode}):\n{result.stderr}"
        )

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"Semgrep returned invalid JSON.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    try:
        payload.setdefault("results", [])
        payload["results"].extend(analyze_python_heuristics(target_path))
    except Exception:
        # Heuristics are additive. They should never break the base Semgrep path.
        pass

    return payload


def _resolve_semgrep_binary() -> str:
    interpreter_bin = Path(sys.executable).parent / "semgrep"
    if interpreter_bin.exists():
        return str(interpreter_bin)

    system_bin = shutil.which("semgrep")
    if system_bin:
        return system_bin

    return "semgrep"


def _build_semgrep_env() -> dict[str, str]:
    env = os.environ.copy()
    uid = getattr(os, "getuid", lambda: "unknown")()
    tmp_home = f"{tempfile.gettempdir()}/guardrail-semgrep-home-{uid}"
    Path(tmp_home).mkdir(parents=True, exist_ok=True)
    Path(f"{tmp_home}/config").mkdir(parents=True, exist_ok=True)
    Path(f"{tmp_home}/cache").mkdir(parents=True, exist_ok=True)
    env.setdefault("HOME", tmp_home)
    env.setdefault("XDG_CONFIG_HOME", f"{tmp_home}/config")
    env.setdefault("XDG_CACHE_HOME", f"{tmp_home}/cache")
    env.setdefault("SEMGREP_SETTINGS_FILE", f"{tmp_home}/settings.yml")
    env.setdefault("SEMGREP_LOG_FILE", f"{tmp_home}/semgrep.log")
    env.setdefault("SEMGREP_VERSION_CHECK_TIMEOUT", "0")
    return env
