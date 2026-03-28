"""
cli/main.py — CLI на Typer.
Команды: guardrail scan <path>, guardrail check <path>, guardrail version
"""

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich import print as rprint
from rich.panel import Panel

# Allow `python cli/main.py ...` from the repository root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.semgrep_runner import run_semgrep
from scanner.parser import parse_findings
from shared.models import EnrichedFinding, Finding, Severity
from shared.redaction import sanitize_snippet

# Попытка импорта AI-слоя Dev 1 (может не быть на момент разработки)
try:
    from ai.orchestrator import enrich_findings
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

app = typer.Typer(
    name="guardrail",
    help="Security scanner with AI explanations.",
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)

__version__ = "0.1.0"

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
    Runs Semgrep + AI explanation (if available).
    """
    target = Path(path)
    if not target.exists():
        error_console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(1)

    if not output_json:
        console.print(f"[dim]Scanning:[/dim] {path}")

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
        raise typer.Exit(0)

    # 3. AI-обогащение (если Dev 1 уже сделал orchestrator)
    if AI_AVAILABLE and not no_ai:
        try:
            enriched = enrich_findings(findings)
        except Exception as e:
            error_console.print(f"[yellow]Warning:[/yellow] AI enrichment failed: {e}")
            enriched = None
    else:
        enriched = None

    # 4. Вывод
    if output_json:
        _print_json(findings, enriched)
    else:
        _print_table(findings, enriched)

    # Exit 1 если есть findings (для pre-commit hook)
    raise typer.Exit(1)


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

    # Краткий вывод для хука
    console.print(f"[red]✗ {len(findings)} security issue(s) found in {path}[/red]")
    for f in findings:
        severity_name = _severity_value(f.severity)
        console.print(f"  [{SEVERITY_COLORS[f.severity]}]{severity_name.upper()}[/] {f.file}:{f.line} — {f.rule_id}")

    raise typer.Exit(1)


@app.command()
def version():
    """Show guardrail version."""
    rprint(f"guardrail [bold]{__version__}[/bold]")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _print_table(findings: list[Finding], enriched: list[EnrichedFinding] | None):
    """Красивый вывод через Rich."""
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


def _print_json(findings: list[Finding], enriched: list[EnrichedFinding] | None):
    """JSON вывод для интеграций."""
    results = enriched if enriched else findings
    output = [_item_to_dict(item) for item in results]
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
