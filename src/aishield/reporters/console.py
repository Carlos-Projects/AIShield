"""Console reporter using Rich.

Renders scan results as formatted Rich panels and tables.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aishield.scanner import ScanResult, Severity


def render_console_report(result: ScanResult) -> str:
    """Render a Rich-formatted console report.

    Args:
        result: ScanResult to render.

    Returns:
        Rich-rendered string (for console.print).
    """
    console = Console(force_terminal=True, width=100)

    with console.capture() as capture:
        # Header
        console.print(Panel(
            f"[bold]AIShield Fine-Tuning Security Scanner[/]\n"
            f"Target: {result.target}\n"
            f"Scan ID: {result.scan_id}\n"
            f"Timestamp: {result.timestamp}",
            title="AIShield Report",
            border_style="blue",
        ))

        # Risk score
        score_color = "red" if result.risk_score >= 70 else "yellow" if result.risk_score >= 40 else "green"
        console.print(f"\n[bold]Risk Score:[/] [{score_color}]{result.risk_score}/100[/{score_color}]")

        # Summary table
        table = Table(title="Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = result.summary.get(sev.value, 0)
            color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "magenta",
                Severity.LOW: "cyan",
                Severity.INFO: "white",
            }[sev]
            table.add_row(f"[{color}]{sev.value}[/{color}]", str(count))

        console.print(table)

        # Findings
        if result.findings:
            console.print("\n[bold]Findings:[/]")
            severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
            sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))

            for f in sorted_findings:
                icon = {
                    Severity.CRITICAL: "[red][!!][/red]",
                    Severity.HIGH: "[yellow][!][/yellow]",
                    Severity.MEDIUM: "[magenta][?][/magenta]",
                    Severity.LOW: "[cyan][i][/cyan]",
                    Severity.INFO: "[dim][~][/dim]",
                }.get(f.severity, "[?]")

                console.print(f"\n  {icon} [bold]{f.check}[/] ({f.severity.value})")
                console.print(f"      {f.detail}")
                if f.recommendation:
                    console.print(f"      [dim]Recommendation: {f.recommendation}[/]")

        else:
            console.print("\n[green]No security findings detected.[/]")

    return capture.get()
