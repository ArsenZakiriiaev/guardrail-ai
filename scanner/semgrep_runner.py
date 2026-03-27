"""
scanner/semgrep_runner.py — запускает Semgrep через subprocess,
возвращает сырой JSON с результатами.
"""

import subprocess
import json
from pathlib import Path


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

    cmd = [
        "semgrep",
        "--config", str(RULES_DIR),
        "--json",
        "--quiet",
        str(target_path),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
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
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"Semgrep returned invalid JSON.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
