"""
watcher/daemon.py — запуск guardrail watch в фоне как демон.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

from rich.console import Console

console = Console(stderr=True)

PID_DIR = ".guardrail"
PID_FILE = "watcher.pid"


def _pid_path(project_root: Path) -> Path:
    d = project_root / PID_DIR
    d.mkdir(exist_ok=True)
    return d / PID_FILE


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def start_daemon(project_root: str | Path, no_ai: bool = False) -> tuple[bool, str]:
    """Запускает watcher в фоне. Возвращает (success, message)."""
    project = Path(project_root).resolve()
    pidfile = _pid_path(project)

    # Проверяем, может уже запущен
    if pidfile.exists():
        try:
            old_pid = int(pidfile.read_text().strip())
            if _is_running(old_pid):
                return False, f"Already running (PID {old_pid}). Use 'guardrail stop' first."
        except (ValueError, OSError):
            pass
        pidfile.unlink(missing_ok=True)

    # Собираем команду
    guardrail_bin = sys.executable.replace("/python", "/guardrail")
    if not Path(guardrail_bin).exists():
        # Fallback: python -m cli.main
        cmd = [sys.executable, "-m", "cli.main", "watch", str(project)]
    else:
        cmd = [guardrail_bin, "watch", str(project)]

    if no_ai:
        cmd.append("--no-ai")
    cmd.append("--no-sound")  # В фоне звук не нужен

    # Запускаем
    log_path = project / PID_DIR / "watcher.log"
    log_file = open(log_path, "w")

    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=log_file,
        start_new_session=True,
        cwd=str(project),
    )

    pidfile.write_text(str(proc.pid))
    return True, f"Started (PID {proc.pid}). Log: {log_path}"


def stop_daemon(project_root: str | Path) -> tuple[bool, str]:
    """Останавливает фоновый watcher."""
    project = Path(project_root).resolve()
    pidfile = _pid_path(project)

    if not pidfile.exists():
        return False, "No running watcher found."

    try:
        pid = int(pidfile.read_text().strip())
    except (ValueError, OSError):
        pidfile.unlink(missing_ok=True)
        return False, "Invalid PID file — removed."

    if not _is_running(pid):
        pidfile.unlink(missing_ok=True)
        return True, "Watcher was not running (stale PID removed)."

    try:
        os.kill(pid, signal.SIGTERM)
        # Ждём до 3 секунд
        import time
        for _ in range(30):
            if not _is_running(pid):
                break
            time.sleep(0.1)
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass

    pidfile.unlink(missing_ok=True)
    return True, f"Stopped (PID {pid})."


def daemon_status(project_root: str | Path) -> dict:
    """Статус фонового watcher."""
    project = Path(project_root).resolve()
    pidfile = _pid_path(project)

    if not pidfile.exists():
        return {"running": False, "pid": None}

    try:
        pid = int(pidfile.read_text().strip())
    except (ValueError, OSError):
        return {"running": False, "pid": None}

    running = _is_running(pid)
    if not running:
        pidfile.unlink(missing_ok=True)

    return {"running": running, "pid": pid if running else None}
