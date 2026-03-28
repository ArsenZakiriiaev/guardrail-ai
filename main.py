"""
cli/main.py — CLI на Typer.
Команды: guardrail scan <path>, guardrail check <path>, guardrail version
"""

import sys
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.panel import Panel
from rich.text import Text

from scanner.semgrep_runner import run_semgrep
from scanner.parser import parse_findings
from shared.models import Finding, Severity

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
        console.print(f"[red]Error:[/red] Path not found: {path}")
        raise typer.Exit(1)

    console.print(f"[dim]Scanning:[/dim] {path}")

    # 1. Запуск Semgrep
    try:
        raw = run_semgrep(path)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(2)
    except Exception as e:
        console.print(f"[red]Scanner error:[/red] {e}")
        raise typer.Exit(2)

    # 2. Парсинг findings
    findings = parse_findings(raw)

    if not findings:
        console.print("[green]✓ No security issues found.[/green]")
        raise typer.Exit(0)

    # 3. AI-обогащение (если Dev 1 уже сделал orchestrator)
    if AI_AVAILABLE and not no_ai:
        try:
            enriched = enrich_findings(findings)
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] AI enrichment failed: {e}")
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
        console.print(f"  [{SEVERITY_COLORS[f.severity]}]{f.severity.value.upper()}[/] {f.file}:{f.line} — {f.rule_id}")

    raise typer.Exit(1)


@app.command()
def version():
    """Show guardrail version."""
    rprint(f"guardrail [bold]{__version__}[/bold]")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _print_table(findings, enriched):
    """Красивый вывод через Rich."""
    count = len(findings)
    console.print(f"\n[red]✗ Found {count} issue(s):[/red]\n")

    results = enriched if enriched else findings

    for item in results:
        # Для Finding и EnrichedFinding поля одинаковые (совместимость)
        color = SEVERITY_COLORS.get(item.severity, "white")
        header = f"[{color}]{item.severity.value.upper()}[/] {item.file}:{item.line}"
        
        body = f"[bold]{item.rule_id}[/bold]\n{item.message}"
        
        if item.snippet:
            body += f"\n\n[dim]{item.snippet}[/dim]"

        # AI explanation (только для EnrichedFinding от Dev 1)
        if hasattr(item, "explanation") and item.explanation:
            body += f"\n\n[blue]AI:[/blue] {item.explanation}"

        if hasattr(item, "fix_available") and item.fix_available:
            body += "\n[green]✓ Fix available — run with --fix[/green]"

        console.print(Panel(body, title=header, expand=False))


def _print_json(findings, enriched):
    """JSON вывод для интеграций."""
    results = enriched if enriched else findings
    output = []
    for item in results:
        if hasattr(item, "to_dict"):
            output.append(item.to_dict())
        else:
            output.append({
                "file": item.file,
                "line": item.line,
                "rule_id": item.rule_id,
                "message": item.message,
                "snippet": item.snippet,
                "severity": item.severity.value,
            })
    print(json.dumps(output, indent=2))


def main():
    app()


if __name__ == "__main__":
    main()
