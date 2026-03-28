"""
cli/main.py — CLI на Typer.
Команды:
  guardrail scan <path>       — полное сканирование
  guardrail check <path>      — быстрая проверка (exit code)
  guardrail watch [path]      — real-time мониторинг
  guardrail hooks install     — установить git-хуки
  guardrail hooks uninstall   — удалить git-хуки
  guardrail hooks status      — статус хуков
  guardrail policy init       — создать .guardrail.yml
  guardrail audit [--limit N] — просмотр аудит-лога
  guardrail version           — версия
"""

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

# Allow `python cli/main.py ...` from the repository root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.semgrep_runner import run_semgrep
from scanner.parser import parse_findings
from shared.models import EnrichedFinding, Finding, Severity
from shared.redaction import sanitize_snippet
from policy.engine import load_policy, init_policy, evaluate_findings, PolicyDecision
from audit.logger import log_event, read_audit_log
from hooks.manager import (
    install_hooks,
    uninstall_hooks,
    hooks_status,
    find_git_root,
)

# Попытка импорта AI-слоя Dev 1 (может не быть на момент разработки)
try:
    from ai.orchestrator import enrich_findings
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

app = typer.Typer(
    name="guardrail",
    help="🛡️ Universal safety layer: scan, watch, block, explain, fix.",
    add_completion=False,
)

# Sub-apps for grouped commands
hooks_app = typer.Typer(help="Manage git hooks (pre-commit, pre-push).")
policy_app = typer.Typer(help="Manage security policies.")
app.add_typer(hooks_app, name="hooks")
app.add_typer(policy_app, name="policy")

console = Console()
error_console = Console(stderr=True)

__version__ = "0.2.0"

# Цвета по severity
SEVERITY_COLORS = {
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


@app.command()
def scan(
    path: str = typer.Argument(..., help="File or directory to scan"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI explanations"),
):
    """
    Scan a file or directory for security issues.
    Runs Semgrep + policy evaluation + AI explanation (if available).
    """
    target = Path(path)
    if not target.exists():
        error_console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(1)

    if not output_json:
        console.print(f"[dim]🛡️  Scanning:[/dim] {path}")

    # Load policy
    project_root = find_git_root(path) or Path(path).resolve().parent
    policy = load_policy(project_root)

    # 1. Запуск Semgrep
    try:
        raw = run_semgrep(path)
    except FileNotFoundError as e:
        error_console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(2)
    except Exception as e:
        error_console.print(f"[red]Scanner error:[/red] {e}")
        raise typer.Exit(2)

    # 2. Парсинг findings
    findings = parse_findings(raw)

    if not findings:
        if output_json:
            print("[]")
        else:
            console.print("[green]✓ No security issues found.[/green]")

        log_event(project_root, "scan", trigger="manual", target=path)
        raise typer.Exit(0)

    # 3. Policy evaluation
    evaluation = evaluate_findings(findings, policy)
    blocked = evaluation["blocked"]
    warned = evaluation["warned"]
    ignored = evaluation["ignored"]

    # 4. AI-обогащение (если Dev 1 уже сделал orchestrator)
    enriched = None
    active_findings = [f for f, _ in blocked] + [f for f, _ in warned]
    if AI_AVAILABLE and not no_ai and active_findings:
        try:
            enriched = enrich_findings(active_findings)
        except Exception as e:
            error_console.print(f"[yellow]Warning:[/yellow] AI enrichment failed: {e}")
            enriched = None

    # 5. Audit log
    log_event(
        project_root,
        "scan",
        findings=findings,
        blocked=len(blocked),
        warned=len(warned),
        ignored=len(ignored),
        trigger="manual",
        target=path,
    )

    # 6. Вывод
    if output_json:
        _print_json(findings, enriched, evaluation)
    else:
        _print_table_with_policy(findings, enriched, evaluation)

    # Exit 1 если есть blocked findings
    if blocked:
        raise typer.Exit(1)
    raise typer.Exit(0)


@app.command()
def check(
    path: str = typer.Argument(..., help="File or directory to check"),
):
    """
    Quick check — exits 0 if clean, 1 if issues found.
    Same as scan but minimal output. Used in CI/pre-commit.
    """
    target = Path(path)
    if not target.exists():
        raise typer.Exit(2)

    try:
        raw = run_semgrep(path)
    except Exception:
        raise typer.Exit(2)

    findings = parse_findings(raw)

    if not findings:
        raise typer.Exit(0)

    # Apply policy — only block if policy says so
    project_root = find_git_root(path) or Path(path).resolve().parent
    policy = load_policy(project_root)
    evaluation = evaluate_findings(findings, policy)
    blocked = evaluation["blocked"]

    if not blocked:
        # Warnings only — pass check
        raise typer.Exit(0)

    # Краткий вывод для хука
    console.print(f"[red]✗ {len(blocked)} blocked issue(s) in {path}[/red]")
    for f, decision in blocked:
        severity_name = _severity_value(f.severity)
        console.print(f"  [{SEVERITY_COLORS[f.severity]}]{severity_name.upper()}[/] {f.file}:{f.line} — {f.rule_id}")

    log_event(
        project_root,
        "pre_commit",
        findings=[f for f, _ in blocked],
        blocked=len(blocked),
        trigger="git_hook",
        target=path,
    )

    raise typer.Exit(1)


@app.command()
def watch(
    path: str = typer.Argument(".", help="Directory to watch (default: current)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI explanations/fixes"),
    no_notify: bool = typer.Option(False, "--no-notify", help="Disable system notifications"),
    no_sound: bool = typer.Option(False, "--no-sound", help="Disable sound alerts"),
):
    """
    🛡️ Real-time protection — watches your files and alerts on every save.
    Shows AI explanations & fix suggestions. Sends system notifications on critical issues.
    Press Ctrl+C to stop.
    """
    from watcher.file_watcher import start_watching

    target = Path(path).resolve()
    if not target.is_dir():
        error_console.print(f"[red]Error:[/red] {path} is not a directory")
        raise typer.Exit(1)

    start_watching(target, no_ai=no_ai, no_notify=no_notify, no_sound=no_sound)


@app.command()
def protect(
    path: str = typer.Argument(".", help="Project root (default: current)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI explanations/fixes"),
):
    """
    🛡️ One command to rule them all.
    Sets up policy, installs git hooks, runs initial scan, then starts real-time watch.
    """
    from watcher.file_watcher import start_watching

    target = Path(path).resolve()
    if not target.is_dir():
        error_console.print(f"[red]Error:[/red] {path} is not a directory")
        raise typer.Exit(1)

    console.print(Panel(
        "[bold]Setting up Guardrail protection...[/bold]",
        title="🛡️  guardrail protect",
        border_style="green",
        expand=False,
    ))

    # 1. Init policy
    policy_path = init_policy(target)
    console.print(f"  [green]✓[/green] Policy: {policy_path}")

    # 2. Install hooks
    success, message = install_hooks(target)
    if success:
        console.print(f"  [green]✓[/green] Hooks: {message}")
    else:
        console.print(f"  [yellow]⚠[/yellow] Hooks: {message}")

    # 3. Initial scan
    console.print(f"  [dim]Начальное сканирование...[/dim]")
    py_files = list(target.rglob("*.py"))
    # Filter out excluded dirs
    policy = load_policy(target)
    exclude_dirs = set(policy.get("exclude_dirs", []))
    py_files = [
        f for f in py_files
        if not any(excl in f.parts for excl in exclude_dirs)
    ]

    total_issues = 0
    for py_file in py_files:
        try:
            raw = run_semgrep(str(py_file))
            findings = parse_findings(raw)
            if findings:
                total_issues += len(findings)
                rel = str(py_file.relative_to(target))
                console.print(f"  [red]  ✗ {rel}: {len(findings)} issue(s)[/red]")
        except Exception:
            pass

    if total_issues:
        console.print(f"\n  [red]Найдено {total_issues} проблем(а). Watcher покажет детали при изменении файлов.[/red]")
    else:
        console.print(f"  [green]✓[/green] Код чист!")

    console.print()

    # 4. Start watching
    start_watching(target, no_ai=no_ai)


# ── Hooks sub-commands ───────────────────────────────────────────────────────

@hooks_app.command("install")
def hooks_install(
    path: str = typer.Argument(".", help="Project root (default: current)"),
):
    """Install Guardrail pre-commit and pre-push git hooks."""
    success, message = install_hooks(path)
    if success:
        console.print(f"[green]✓[/green] {message}")

        project_root = find_git_root(path) or Path(path).resolve()
        log_event(project_root, "hook_install", trigger="manual", details=message)
    else:
        error_console.print(f"[red]✗[/red] {message}")
        raise typer.Exit(1)


@hooks_app.command("uninstall")
def hooks_uninstall(
    path: str = typer.Argument(".", help="Project root (default: current)"),
):
    """Remove Guardrail git hooks (restores backups if they exist)."""
    success, message = uninstall_hooks(path)
    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        error_console.print(f"[red]✗[/red] {message}")
        raise typer.Exit(1)


@hooks_app.command("status")
def hooks_show_status(
    path: str = typer.Argument(".", help="Project root (default: current)"),
):
    """Show status of Guardrail git hooks."""
    status = hooks_status(path)

    table = Table(title="Git Hooks Status", show_header=True)
    table.add_column("Hook", style="bold")
    table.add_column("Status")

    status_styles = {
        "installed": "[green]✓ Installed[/green]",
        "not_installed": "[dim]Not installed[/dim]",
        "other": "[yellow]⚠ Other hook present[/yellow]",
        "no_git": "[red]✗ Not a git repository[/red]",
    }

    for hook, st in status.items():
        table.add_row(hook, status_styles.get(st, st))

    console.print(table)


# ── Policy sub-commands ──────────────────────────────────────────────────────

@policy_app.command("init")
def policy_init(
    path: str = typer.Argument(".", help="Project root (default: current)"),
):
    """Create a .guardrail.yml policy file in the project root."""
    target = Path(path).resolve()
    created = init_policy(target)
    console.print(f"[green]✓[/green] Policy file: {created}")

    log_event(target, "policy_init", trigger="manual", target=str(created))


@policy_app.command("show")
def policy_show(
    path: str = typer.Argument(".", help="Project root (default: current)"),
):
    """Show the active policy configuration."""
    target = Path(path).resolve()
    policy = load_policy(target)

    console.print(Panel(
        f"[bold]block_severity:[/bold] {policy.get('block_severity', 'high')}\n"
        f"[bold]warn_severity:[/bold] {policy.get('warn_severity', 'medium')}\n"
        f"[bold]ignored_rules:[/bold] {policy.get('ignored_rules', [])}\n"
        f"[bold]watched_extensions:[/bold] {', '.join(policy.get('watched_extensions', []))}\n"
        f"[bold]exclude_dirs:[/bold] {', '.join(policy.get('exclude_dirs', []))}",
        title="🛡️ Active Policy",
        expand=False,
    ))


# ── Audit command ────────────────────────────────────────────────────────────

@app.command()
def audit(
    path: str = typer.Argument(".", help="Project root (default: current)"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of entries to show"),
    event: str = typer.Option(None, "--event", "-e", help="Filter by event type"),
):
    """View the security audit log."""
    target = Path(path).resolve()
    entries = read_audit_log(target, limit=limit, event_filter=event)

    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        raise typer.Exit(0)

    table = Table(title=f"Audit Log (last {len(entries)} entries)", show_header=True)
    table.add_column("Time", style="dim", width=20)
    table.add_column("Event", style="bold")
    table.add_column("Target", max_width=30)
    table.add_column("Blocked", justify="right")
    table.add_column("Warned", justify="right")
    table.add_column("Details", max_width=40)

    for entry in entries:
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        evt = entry.get("event", "")
        tgt = entry.get("target", "")
        summary = entry.get("summary", {})
        blocked = str(summary.get("blocked", 0))
        warned = str(summary.get("warned", 0))
        details = entry.get("details", "")

        blocked_style = f"[red]{blocked}[/red]" if int(blocked) > 0 else blocked
        warned_style = f"[yellow]{warned}[/yellow]" if int(warned) > 0 else warned

        table.add_row(ts, evt, tgt, blocked_style, warned_style, details)

    console.print(table)


@app.command()
def version():
    """Show guardrail version."""
    rprint(f"guardrail [bold]{__version__}[/bold]")


@app.command()
def start(
    path: str = typer.Argument(".", help="Project root (default: current)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI enrichment"),
):
    """
    Start Guardrail watcher in the background (daemon mode).
    Continues protecting even after you close the terminal.
    """
    from watcher.daemon import start_daemon

    target = Path(path).resolve()
    success, message = start_daemon(target, no_ai=no_ai)
    if success:
        console.print(f"[green]✓[/green] {message}")
        log_event(target, "daemon_start", trigger="manual", target=str(target), details=message)
    else:
        error_console.print(f"[red]✗[/red] {message}")
        raise typer.Exit(1)


@app.command()
def stop(
    path: str = typer.Argument(".", help="Project root (default: current)"),
):
    """Stop the background Guardrail watcher."""
    from watcher.daemon import stop_daemon

    target = Path(path).resolve()
    success, message = stop_daemon(target)
    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        error_console.print(f"[yellow]⚠[/yellow] {message}")


@app.command()
def status(
    path: str = typer.Argument(".", help="Project root (default: current)"),
):
    """Show status of Guardrail: hooks, watcher, policy."""
    from watcher.daemon import daemon_status

    target = Path(path).resolve()

    # Watcher status
    d_status = daemon_status(target)

    # Hooks status
    h_status = hooks_status(target)

    # Policy
    policy_file = target / ".guardrail.yml"

    table = Table(title="🛡️ Guardrail Status", show_header=True, expand=False)
    table.add_column("Component", style="bold")
    table.add_column("Status")

    # Watcher
    if d_status["running"]:
        table.add_row("Watcher (daemon)", f"[green]Running[/green] (PID {d_status['pid']})")
    else:
        table.add_row("Watcher (daemon)", "[dim]Not running[/dim]")

    # Hooks
    hook_styles = {
        "installed": "[green]✓ Installed[/green]",
        "not_installed": "[dim]Not installed[/dim]",
        "other": "[yellow]Other hook[/yellow]",
        "no_git": "[red]No git repo[/red]",
    }
    for hook, st in h_status.items():
        table.add_row(f"Hook: {hook}", hook_styles.get(st, st))

    # Policy
    if policy_file.exists():
        table.add_row("Policy", f"[green]✓[/green] {policy_file}")
    else:
        table.add_row("Policy", "[dim]Default (no .guardrail.yml)[/dim]")

    # AI
    ai_mode = os.getenv("GUARDRAIL_LLM_MODE", "mock")
    table.add_row("AI mode", f"[cyan]{ai_mode}[/cyan]")

    console.print(table)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _print_table_with_policy(
    findings: list[Finding],
    enriched: list[EnrichedFinding] | None,
    evaluation: dict,
):
    """Красивый вывод с учётом политик (blocked/warned/ignored)."""
    blocked = evaluation["blocked"]
    warned = evaluation["warned"]
    ignored = evaluation["ignored"]

    if blocked:
        console.print(f"\n[red]🚫 {len(blocked)} BLOCKED issue(s):[/red]\n")
        _render_finding_panels(blocked, enriched, "red", "BLOCKED")

    if warned:
        console.print(f"\n[yellow]⚠️  {len(warned)} warning(s):[/yellow]\n")
        _render_finding_panels(warned, enriched, "yellow", "WARNING")

    if ignored:
        console.print(f"[dim]  ({len(ignored)} ignored by policy)[/dim]")

    # Summary line
    parts = []
    if blocked:
        parts.append(f"[red]{len(blocked)} blocked[/red]")
    if warned:
        parts.append(f"[yellow]{len(warned)} warnings[/yellow]")
    if ignored:
        parts.append(f"[dim]{len(ignored)} ignored[/dim]")
    console.print(f"\n  Summary: {' | '.join(parts)}\n")


def _render_finding_panels(
    items: list[tuple],
    enriched: list[EnrichedFinding] | None,
    border_color: str,
    label: str,
):
    """Рендерит панели для списка (finding, decision) с обогащением."""
    enriched_map = {}
    if enriched:
        for e in enriched:
            key = (e.file, e.line, e.rule_id)
            enriched_map[key] = e

    for finding, decision in items:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        header = f"[{color}]{label}[/] {finding.file}:{finding.line}"
        body = f"[bold]{finding.rule_id}[/bold]\n{finding.message}"
        snippet = sanitize_snippet(finding.snippet, finding.type, finding.rule_id)

        if snippet:
            body += f"\n\n[dim]{snippet}[/dim]"

        # Check for enrichment
        key = (finding.file, finding.line, finding.rule_id)
        enriched_item = enriched_map.get(key)
        if enriched_item:
            body += f"\n\n[blue]💡 Summary:[/blue] {enriched_item.summary}"
            body += f"\n[blue]⚡ Risk:[/blue] {enriched_item.risk}"
            body += f"\n[blue]🔧 Fix:[/blue] {enriched_item.fix}"
            if enriched_item.confidence:
                body += f"\n[blue]📊 Confidence:[/blue] {enriched_item.confidence}"

        console.print(Panel(body, title=header, border_style=border_color, expand=False))


def _print_table(findings: list[Finding], enriched: list[EnrichedFinding] | None):
    """Красивый вывод через Rich (legacy, без policy)."""
    count = len(findings)
    console.print(f"\n[red]✗ Found {count} issue(s):[/red]\n")

    results = enriched if enriched else findings

    for item in results:
        color = SEVERITY_COLORS.get(item.severity, "white")
        header = f"[{color}]{_severity_value(item.severity).upper()}[/] {item.file}:{item.line}"
        body = f"[bold]{item.rule_id}[/bold]\n{item.message}"
        snippet = sanitize_snippet(item.snippet, item.type, item.rule_id)

        if snippet:
            body += f"\n\n[dim]{snippet}[/dim]"

        if isinstance(item, EnrichedFinding):
            body += f"\n\n[blue]Summary:[/blue] {item.summary}"
            body += f"\n[blue]Risk:[/blue] {item.risk}"
            body += f"\n[blue]Fix:[/blue] {item.fix}"
            if item.confidence:
                body += f"\n[blue]Confidence:[/blue] {item.confidence}"

        console.print(Panel(body, title=header, expand=False))


def _print_json(findings: list[Finding], enriched: list[EnrichedFinding] | None, evaluation: dict | None = None):
    """JSON вывод для интеграций."""
    results = enriched if enriched else findings
    output = []

    for item in results:
        d = _item_to_dict(item)
        if evaluation:
            # Add policy decision
            for f, decision in evaluation.get("blocked", []):
                if f.file == item.file and f.line == item.line and f.rule_id == item.rule_id:
                    d["policy_action"] = "blocked"
                    break
            else:
                for f, decision in evaluation.get("warned", []):
                    if f.file == item.file and f.line == item.line and f.rule_id == item.rule_id:
                        d["policy_action"] = "warned"
                        break
                else:
                    d["policy_action"] = "ignored"
        output.append(d)

    print(json.dumps(output, indent=2))


def _item_to_dict(item: Finding | EnrichedFinding) -> dict:
    snippet = sanitize_snippet(item.snippet, item.type, item.rule_id)

    if hasattr(item, "to_dict"):
        payload = item.to_dict()
        payload["snippet"] = snippet
        return payload

    return {
        "file": item.file,
        "line": item.line,
        "rule_id": item.rule_id,
        "type": item.type,
        "message": item.message,
        "snippet": snippet,
        "severity": _severity_value(item.severity),
    }


def _severity_value(severity: Severity | str) -> str:
    if isinstance(severity, Severity):
        return severity.value
    return str(severity)


def main():
    app()


if __name__ == "__main__":
    main()
