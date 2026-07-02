"""FailFast CLI — Command-line interface for production-readiness scanning.

Usage:
    failfast scan <path>                     Full scan
    failfast scan <path> --diff main         Diff-only scan
    failfast scan <path> --format json       Output as JSON
    failfast check <path> --category security    Single category
    failfast explain FF-RETRY-001            Explain a finding rule
"""

from __future__ import annotations

import json
import sys

# Reconfigure standard output and error to UTF-8 to prevent encoding crashes on Windows
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from failfast import __version__
from failfast.engine import get_rule_explanation, run_check, run_scan, run_scan_diff
from failfast.models import AnalysisContext, Category, Scorecard, Verdict

console = Console()


def _verdict_color(verdict: Verdict) -> str:
    """Map verdict to rich color name."""
    return {"pass": "green", "fail": "red", "warn": "yellow"}.get(verdict.value, "white")


def _render_scorecard(scorecard: Scorecard) -> None:
    """Render a scorecard to the terminal using Rich."""
    verdict_color = _verdict_color(scorecard.verdict)
    verdict_text = Text(scorecard.verdict.value.upper(), style=f"bold {verdict_color}")

    # Header panel
    console.print()
    console.print(
        Panel(
            Text.assemble(
                "Verdict: ",
                verdict_text,
                f"\n{scorecard.summary}",
                f"\nPath: {scorecard.scan_path}",
                f"\nProfile: {scorecard.profile}",
            ),
            title="[bold]FailFast Production Readiness[/bold]",
            border_style=verdict_color,
        )
    )

    # Category summary table
    cat_table = Table(title="Category Summary", show_header=True, header_style="bold")
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Verdict", justify="center")
    cat_table.add_column("Blockers", justify="right")
    cat_table.add_column("Warnings", justify="right")

    for cat in Category:
        result = scorecard.categories.get(cat)
        if result:
            v_color = _verdict_color(result.verdict)
            cat_table.add_row(
                cat.value,
                Text(result.verdict.value.upper(), style=f"bold {v_color}"),
                str(result.blocker_count),
                str(result.warning_count),
            )
        else:
            cat_table.add_row(cat.value, Text("PASS", style="bold green"), "0", "0")

    console.print(cat_table)

    # Blockers
    if scorecard.blockers:
        console.print()
        console.print("[bold red]⛔ BLOCKERS[/bold red]")
        console.print()
        for i, finding in enumerate(scorecard.blockers, 1):
            console.print(f"  [bold red]{i}.[/bold red] [{finding.id}] {finding.title}")
            console.print(f"     [dim]{finding.file_path}:{finding.line}[/dim]")
            console.print(f"     [yellow]Why:[/yellow] {finding.why}")
            console.print(f"     [green]Fix:[/green] {finding.fix}")
            if finding.standard_refs:
                refs = ", ".join(finding.standard_refs)
                console.print(f"     [blue]Refs:[/blue] {refs}")
            console.print()

    # Warnings
    if scorecard.warnings:
        console.print("[bold yellow]⚠ WARNINGS[/bold yellow]")
        console.print()
        for i, finding in enumerate(scorecard.warnings, 1):
            console.print(f"  [yellow]{i}.[/yellow] [{finding.id}] {finding.title}")
            console.print(f"     [dim]{finding.file_path}:{finding.line}[/dim]")
            console.print(f"     [green]Fix:[/green] {finding.fix}")
            console.print()


def _render_json(scorecard: Scorecard) -> None:
    """Render scorecard as JSON to stdout."""
    from failfast.reporters.json_reporter import to_json

    click.echo(to_json(scorecard))


def _render_markdown(scorecard: Scorecard) -> None:
    """Render scorecard as Markdown to stdout."""
    from failfast.reporters.markdown_reporter import to_markdown

    click.echo(to_markdown(scorecard))


def _render_sarif(scorecard: Scorecard) -> None:
    """Render scorecard as SARIF to stdout."""
    from failfast.reporters.sarif_reporter import to_sarif

    click.echo(to_sarif(scorecard))


@click.group()
@click.version_option(version=__version__, prog_name="failfast")
def main() -> None:
    """FailFast — Production-readiness reviewer for Python code.

    Checks security, reliability, API quality, maintainability, and dependencies.
    Not just a linter — a production gate.
    """


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--profile", default="python-api", help="Analysis profile (default: python-api)")
@click.option("--diff", "base_ref", default=None, help="Only scan files changed since this git ref")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "json", "markdown", "sarif"]),
    default="rich",
    help="Output format",
)
@click.option("--max-complexity", default=15, help="Max cyclomatic complexity (default: 15)")
def scan(
    path: str,
    profile: str,
    base_ref: str | None,
    output_format: str,
    max_complexity: int,
) -> None:
    """Scan a Python project for production-readiness.

    PATH is the directory or file to scan.
    """
    import os

    abs_path = os.path.abspath(path)
    context = AnalysisContext(
        repo_path=abs_path,
        profile=profile,
        max_complexity=max_complexity,
    )

    scorecard = run_scan_diff(context, base_ref=base_ref) if base_ref else run_scan(context)

    if output_format == "json":
        _render_json(scorecard)
    elif output_format == "markdown":
        _render_markdown(scorecard)
    elif output_format == "sarif":
        _render_sarif(scorecard)
    else:
        _render_scorecard(scorecard)

    # Exit code: 0=pass, 1=fail (blockers), 2=warn
    if scorecard.verdict == Verdict.FAIL:
        sys.exit(1)
    elif scorecard.verdict == Verdict.WARN:
        sys.exit(2)
    else:
        sys.exit(0)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--category",
    required=True,
    type=click.Choice([c.value for c in Category]),
    help="Category to check",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "json"]),
    default="rich",
    help="Output format",
)
def check(path: str, category: str, output_format: str) -> None:
    """Run a single analysis category against a path."""
    import os

    abs_path = os.path.abspath(path)
    context = AnalysisContext(repo_path=abs_path)
    cat = Category(category)
    result = run_check(context, category=cat)

    if output_format == "json":
        output = {
            "category": result.category.value,
            "verdict": result.verdict.value,
            "finding_count": len(result.findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "file": f.file_path,
                    "line": f.line,
                    "blocking": f.blocking,
                    "fix": f.fix,
                }
                for f in result.findings
            ],
        }
        click.echo(json.dumps(output, indent=2))
    else:
        v_color = _verdict_color(result.verdict)
        console.print(
            Panel(
                f"Category: {result.category.value}\n"
                f"Verdict: [{v_color}]{result.verdict.value.upper()}[/{v_color}]\n"
                f"Findings: {len(result.findings)}",
                title=f"[bold]FailFast — {category}[/bold]",
                border_style=v_color,
            )
        )
        for f in result.findings:
            marker = "⛔" if f.blocking else "⚠"
            console.print(f"  {marker} [{f.id}] {f.title}")
            console.print(f"     [dim]{f.file_path}:{f.line}[/dim]")
            console.print(f"     [green]Fix:[/green] {f.fix}")
            console.print()


@main.command()
@click.argument("finding_id")
def explain(finding_id: str) -> None:
    """Get a detailed explanation for a FailFast finding rule."""
    explanation = get_rule_explanation(finding_id)

    if explanation is None:
        console.print(f"[red]Unknown finding ID: {finding_id}[/red]")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold]{explanation.get('title', '')}[/bold]\n\n"
            f"{explanation.get('description', '')}\n\n"
            f"[yellow]Why it matters:[/yellow]\n{explanation.get('why', '')}\n\n"
            f"[green]How to fix:[/green]\n{explanation.get('fix', '')}\n\n"
            f"[blue]References:[/blue] {', '.join(explanation.get('standard_refs', []))}",  # type: ignore[arg-type]
            title=f"[bold]Rule: {finding_id}[/bold]",
        )
    )


if __name__ == "__main__":
    main()
