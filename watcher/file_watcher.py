"""
watcher/file_watcher.py — боевой real-time файловый наблюдатель.

Следит за проектом, при сохранении файла:
  1. Мгновенно сканирует Semgrep-ом
  2. Оценивает по политике (block/warn/ignore)
  3. Получает AI-объяснение и фикс
  4. Показывает красивый алерт с полной диагностикой
  5. Отправляет macOS/Linux-уведомление (звук)
  6. Пишет всё в аудит-лог
"""

from __future__ import annotations

import os
import subprocess
import sys
import platform
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.rule import Rule

from scanner.semgrep_runner import run_semgrep
from scanner.parser import parse_findings
from shared.models import Finding, Severity
from shared.redaction import sanitize_snippet
from policy.engine import load_policy, evaluate_findings, PolicyDecision
from audit.logger import log_event

# AI — подключаем объяснения и фиксы
try:
    from ai.explain import explain_finding
    from ai.fix import fix_finding
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False


console = Console(stderr=True)

SEVERITY_COLORS = {
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

SEVERITY_ICONS = {
    Severity.LOW: "ℹ️ ",
    Severity.MEDIUM: "⚠️ ",
    Severity.HIGH: "🚨",
    Severity.CRITICAL: "💀",
}


# ── Системные уведомления (macOS / Linux) ────────────────────────────────

def _notify_system(title: str, message: str, urgent: bool = False) -> None:
    """Отправляет системное уведомление."""
    system = platform.system()
    try:
        if system == "Darwin":
            sound = 'sound name "Funk"' if urgent else ""
            script = (
                f'display notification "{_escape_applescript(message)}" '
                f'with title "{_escape_applescript(title)}" {sound}'
            )
            subprocess.Popen(
                ["osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        elif system == "Linux":
            urgency = "critical" if urgent else "normal"
            subprocess.Popen(
                ["notify-send", f"--urgency={urgency}", title, message],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except FileNotFoundError:
        pass


def _escape_applescript(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _bell() -> None:
    """Звуковой сигнал в терминале."""
    sys.stderr.write("\a")
    sys.stderr.flush()


# ── Debouncer ────────────────────────────────────────────────────────────────

class _ScanDebouncer:
    def __init__(self, delay: float = 0.8):
        self._delay = delay
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def debounce(self, key: str, callback: Callable, *args) -> None:
        with self._lock:
            existing = self._timers.get(key)
            if existing:
                existing.cancel()
            timer = threading.Timer(self._delay, callback, args)
            timer.daemon = True
            self._timers[key] = timer
            timer.start()

    def cancel_all(self) -> None:
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()


# ── Кэш findings ────────────────────────────────────────────────────────────

class _FindingsCache:
    """Не спамить одними и теми же findings если файл не менялся по существу."""

    def __init__(self):
        self._cache: dict[str, set[str]] = {}

    def get_new(self, file_path: str, findings: list[Finding]) -> list[Finding]:
        existing = self._cache.get(file_path, set())
        new = []
        current_keys = set()
        for f in findings:
            key = f"{f.rule_id}:{f.line}:{f.message}"
            current_keys.add(key)
            if key not in existing:
                new.append(f)
        self._cache[file_path] = current_keys
        return new

    def clear(self, file_path: str) -> None:
        self._cache.pop(file_path, None)


# ── Event Handler ────────────────────────────────────────────────────────────

class GuardrailEventHandler(FileSystemEventHandler):

    def __init__(
        self,
        project_root: Path,
        policy: dict,
        watched_extensions: set[str],
        exclude_dirs: set[str],
        max_file_size: int,
        *,
        enable_ai: bool = True,
        enable_notify: bool = True,
        enable_sound: bool = True,
    ):
        super().__init__()
        self._project_root = project_root
        self._policy = policy
        self._watched_extensions = watched_extensions
        self._exclude_dirs = exclude_dirs
        self._max_file_size = max_file_size
        self._enable_ai = enable_ai and AI_AVAILABLE
        self._enable_notify = enable_notify
        self._enable_sound = enable_sound
        self._debouncer = _ScanDebouncer(delay=0.8)
        self._cache = _FindingsCache()
        self._lock = threading.Lock()

        self.scans = 0
        self.total_findings = 0
        self.total_blocked = 0
        self.total_warned = 0
        self.clean_saves = 0

    def on_modified(self, event):
        if not isinstance(event, FileModifiedEvent):
            return
        self._handle(event.src_path)

    def on_created(self, event):
        if not isinstance(event, FileCreatedEvent):
            return
        self._handle(event.src_path)

    def _handle(self, src_path: str) -> None:
        path = Path(src_path)

        if not path.is_file():
            return
        if path.suffix not in self._watched_extensions:
            return
        for part in path.parts:
            if part in self._exclude_dirs:
                return
        try:
            if path.stat().st_size > self._max_file_size:
                return
        except OSError:
            return
        if path.name.startswith(".") or path.name.startswith("~"):
            return

        self._debouncer.debounce(str(path), self._scan_file, str(path))

    def _scan_file(self, file_path: str) -> None:
        with self._lock:
            self.scans += 1

        try:
            rel = str(Path(file_path).relative_to(self._project_root))
        except ValueError:
            rel = file_path

        try:
            raw = run_semgrep(file_path)
            findings = parse_findings(raw)
        except Exception as e:
            console.print(f"  [dim]⚠ scan error {rel}: {e}[/dim]")
            return

        if not findings:
            with self._lock:
                self.clean_saves += 1
            self._cache.clear(file_path)
            console.print(f"  [green]✓[/green] [dim]{rel}[/dim]")
            return

        new_findings = self._cache.get_new(file_path, findings)
        if not new_findings:
            return

        evaluation = evaluate_findings(new_findings, self._policy)
        blocked = evaluation["blocked"]
        warned = evaluation["warned"]

        with self._lock:
            self.total_findings += len(new_findings)
            self.total_blocked += len(blocked)
            self.total_warned += len(warned)

        log_event(
            self._project_root,
            "watch_alert",
            findings=new_findings,
            blocked=len(blocked),
            warned=len(warned),
            ignored=len(evaluation["ignored"]),
            trigger="file_save",
            target=rel,
        )

        if not blocked and not warned:
            return

        # ── Вывод алертов ────────────────────────────────────────────────

        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print()
        console.print(Rule(
            f"[bold] {timestamp}  {rel} [/bold]",
            style="red" if blocked else "yellow",
        ))

        for finding, decision in blocked:
            self._render_alert(finding, rel, "BLOCKED", "red")

        for finding, decision in warned:
            self._render_alert(finding, rel, "WARNING", "yellow")

        parts = []
        if blocked:
            parts.append(f"[bold red]{len(blocked)} BLOCKED[/bold red]")
        if warned:
            parts.append(f"[bold yellow]{len(warned)} WARNING[/bold yellow]")
        console.print(f"\n  → {' + '.join(parts)} in [bold]{rel}[/bold]")

        if blocked:
            console.print(
                f"  [dim]Коммит с этим файлом будет заблокирован. "
                f"Исправь и сохрани — проверю снова.[/dim]"
            )
        console.print()

        # ── Системные уведомления ────────────────────────────────────────
        has_high = any(
            f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f, _ in blocked
        )

        if self._enable_sound and blocked:
            _bell()

        if self._enable_notify and blocked:
            title = f"🚨 Guardrail: {len(blocked)} проблем(а)"
            body_lines = []
            for f, _ in blocked[:3]:
                body_lines.append(f"• {f.rule_id} ({rel}:{f.line})")
            if len(blocked) > 3:
                body_lines.append(f"  ... и ещё {len(blocked) - 3}")
            _notify_system(title, "\n".join(body_lines), urgent=has_high)

    def _render_alert(
        self,
        finding: Finding,
        rel_path: str,
        label: str,
        color: str,
    ) -> None:
        """Рендерит панель: ошибка + AI объяснение + фикс."""
        icon = SEVERITY_ICONS.get(finding.severity, "❌")
        snippet = sanitize_snippet(finding.snippet, finding.type, finding.rule_id)

        body = f"[bold]{finding.rule_id}[/bold]\n"
        body += f"{finding.message}\n"
        if snippet:
            body += f"\n[dim]  {snippet}[/dim]\n"

        # AI enrichment
        if self._enable_ai:
            try:
                explanation = explain_finding(finding)
                body += f"\n[blue]💡 Что случилось:[/blue] {explanation.summary}"
                body += f"\n[red]⚡ Риск:[/red] {explanation.risk}"
                body += f"\n[green]🔧 Как исправить:[/green] {explanation.fix}"
            except Exception:
                pass

            try:
                fix = fix_finding(finding)
                if fix.fixed_code:
                    body += f"\n\n[bold green]📝 Исправленный код:[/bold green]"
                    fix_lines = fix.fixed_code.strip().splitlines()[:8]
                    fix_preview = "\n".join(f"  {line}" for line in fix_lines)
                    body += f"\n[green]{fix_preview}[/green]"
                    if fix.explanation:
                        body += f"\n[dim]  ↳ {fix.explanation}[/dim]"
            except Exception:
                pass

        header = f"{icon} [{color}]{label}[/{color}] {rel_path}:{finding.line}"
        console.print(Panel(body, title=header, border_style=color, expand=False))

    def stop(self):
        self._debouncer.cancel_all()


# ── Запуск ───────────────────────────────────────────────────────────────────

def start_watching(
    project_root: str | Path,
    *,
    no_ai: bool = False,
    no_notify: bool = False,
    no_sound: bool = False,
) -> None:
    """Запускает real-time защиту проекта. Блокирующий — до Ctrl+C."""
    project = Path(project_root).resolve()
    if not project.is_dir():
        console.print(f"[red]Error:[/red] {project} is not a directory")
        return

    policy = load_policy(project)
    watched_extensions = set(policy.get("watched_extensions", [".py"]))
    exclude_dirs = set(policy.get("exclude_dirs", []))
    max_file_size = policy.get("max_file_size", 1_048_576)

    handler = GuardrailEventHandler(
        project_root=project,
        policy=policy,
        watched_extensions=watched_extensions,
        exclude_dirs=exclude_dirs,
        max_file_size=max_file_size,
        enable_ai=not no_ai,
        enable_notify=not no_notify,
        enable_sound=not no_sound,
    )

    observer = Observer()
    observer.schedule(handler, str(project), recursive=True)
    observer.start()

    ai_status = "[green]ON[/green]" if (AI_AVAILABLE and not no_ai) else "[dim]OFF[/dim]"
    notify_status = "[green]ON[/green]" if not no_notify else "[dim]OFF[/dim]"

    console.print(Panel(
        f"[bold green]Guardrail активен[/bold green]\n\n"
        f"  Проект:     [cyan]{project}[/cyan]\n"
        f"  Расширения: {', '.join(sorted(watched_extensions))}\n"
        f"  Политика:   severity >= [red]{policy.get('block_severity', 'high')}[/red] → блок, "
        f">= [yellow]{policy.get('warn_severity', 'medium')}[/yellow] → предупреждение\n"
        f"  AI:         {ai_status}  |  Уведомления: {notify_status}\n\n"
        f"  [dim]Пиши код — я слежу. Сохраняй файл — проверю мгновенно.[/dim]\n"
        f"  [dim]Ctrl+C для остановки.[/dim]",
        title="🛡️  Real-time Guard",
        border_style="green",
        expand=False,
    ))

    log_event(project, "watch_start", trigger="manual", target=str(project))

    try:
        while observer.is_alive():
            observer.join(timeout=1)
    except KeyboardInterrupt:
        console.print("\n[dim]Останавливаю...[/dim]")
    finally:
        handler.stop()
        observer.stop()
        observer.join()

        console.print()
        console.print(Panel(
            f"  Сканирований: [bold]{handler.scans}[/bold]\n"
            f"  Чистых сохранений: [green]{handler.clean_saves}[/green]\n"
            f"  Найдено проблем: [bold]{handler.total_findings}[/bold]\n"
            f"  Заблокировано: [red]{handler.total_blocked}[/red]\n"
            f"  Предупреждений: [yellow]{handler.total_warned}[/yellow]",
            title="📊 Итоги сессии",
            border_style="blue",
            expand=False,
        ))

        log_event(
            project,
            "watch_stop",
            trigger="manual",
            target=str(project),
            details=f"scans={handler.scans} clean={handler.clean_saves} "
                    f"found={handler.total_findings} blocked={handler.total_blocked}",
        )
