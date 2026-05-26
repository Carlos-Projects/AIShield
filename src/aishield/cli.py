"""AIShield CLI — Security scanner for the LLM fine-tuning lifecycle.

Usage:
    aishield scan <path>          Full security scan
    aishield dataset <path>       Dataset poisoning analysis
    aishield lora <path>          LoRA adapter analysis
    aishield weights <path>       Weight integrity check
    aishield pipeline <path>      Pipeline audit
    aishield manifest <path>      Generate weight manifest
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from aishield.lora.diff import generate_lora_diff_report
from aishield.pipeline.compliance import check_compliance
from aishield.pipeline.supply_chain import generate_supply_chain_report
from aishield.reporters.html import save_html_report
from aishield.scanner import generate_report, scan_directory
from aishield.weights.fingerprinter import generate_fingerprint
from aishield.weights.manifest import generate_manifest, save_manifest, verify_manifest

console = Console()
app = typer.Typer(
    name="aishield",
    help="Security scanner for the LLM fine-tuning lifecycle",
    add_completion=False,
)


def _resolve_path(path: Path) -> Path:
    """Resolve and validate a path argument."""
    resolved = path.resolve()
    if not resolved.exists():
        console.print(f"[red]Error:[/] {path} does not exist")
        raise typer.Exit(1)
    return resolved


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to model or project directory"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    html_output: Path = typer.Option(None, "--html", "-H", help="Output as HTML report"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    scan_types: str = typer.Option(
        "all", "--types", "-t", help="Scan types: all,dataset,lora,weights,pipeline"
    ),
    redact_paths: bool = typer.Option(
        False, "--redact-paths", "-r", help="Redact home directories from output paths"
    ),
):
    """Perform a full security scan of a model directory."""
    path = _resolve_path(path)

    valid_scan_types = {"dataset", "lora", "weights", "pipeline"}
    types = None if scan_types == "all" else scan_types.split(",")
    if types is not None:
        invalid = [t for t in types if t not in valid_scan_types]
        if invalid:
            raise typer.BadParameter(f"Invalid scan types: {', '.join(invalid)}. Valid: {', '.join(sorted(valid_scan_types))}")
    result = scan_directory(path, scan_types=types, redact_paths=redact_paths)

    if json_output:
        output_text = result.model_dump_json(indent=2)
    elif html_output:
        save_html_report(result, str(html_output))
        console.print(f"[green]HTML report saved to {html_output}[/]")
        return
    else:
        output_text = generate_report(result, fmt="text")

    if output:
        output.write_text(output_text)
        console.print(f"[green]Report saved to {output}[/]")
    else:
        if json_output:
            console.print(output_text)
        else:
            console.print(Panel(output_text, title="AIShield Scan Results", border_style="blue"))

    # Exit with code based on severity
    if result.summary.get("critical", 0) > 0:
        raise typer.Exit(2)
    elif result.summary.get("high", 0) > 0:
        raise typer.Exit(1)


@app.command()
def dataset(
    path: Path = typer.Argument(..., help="Path to dataset or model directory"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
):
    """Analyze dataset for poisoning and provenance issues."""
    path = _resolve_path(path)
    result = scan_directory(path, scan_types=["dataset"])

    if json_output:
        console.print(result.model_dump_json(indent=2))
    else:
        console.print(
            Panel(
                generate_report(result, fmt="text"),
                title="Dataset Analysis",
                border_style="yellow",
            )
        )


@app.command()
def lora(
    path: Path = typer.Argument(..., help="Path to LoRA adapter directory"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    diff: bool = typer.Option(False, "--diff", "-d", help="Show layer diff analysis"),
):
    """Analyze LoRA adapters for backdoors and suspicious modifications."""
    path = _resolve_path(path)
    result = scan_directory(path, scan_types=["lora"])

    if diff:
        console.print(
            Panel(
                generate_lora_diff_report(path),
                title="LoRA Diff Analysis",
                border_style="cyan",
            )
        )

    if json_output:
        console.print(result.model_dump_json(indent=2))
    else:
        console.print(
            Panel(
                generate_report(result, fmt="text"),
                title="LoRA Analysis",
                border_style="cyan",
            )
        )


@app.command()
def weights(
    path: Path = typer.Argument(..., help="Path to model directory"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    fingerprint: bool = typer.Option(
        False, "--fingerprint", "-f", help="Generate model fingerprint"
    ),
):
    """Check model weight integrity and generate fingerprints."""
    path = _resolve_path(path)
    result = scan_directory(path, scan_types=["weights"])

    if fingerprint:
        fp = generate_fingerprint(path)
        console.print(f"[green]Fingerprint: {fp['fingerprint'][:16]}...[/]")
        console.print(f"  Files: {fp['file_count']}")
        console.print(f"  Saved to: {path / 'model_fingerprint.json'}")

    if json_output:
        console.print(result.model_dump_json(indent=2))
    else:
        console.print(
            Panel(
                generate_report(result, fmt="text"),
                title="Weight Integrity",
                border_style="magenta",
            )
        )


@app.command()
def pipeline(
    path: Path = typer.Argument(..., help="Path to project directory"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    compliance: str = typer.Option(
        None, "--compliance", "-c", help="Check compliance: nist, owasp"
    ),
):
    """Audit fine-tuning pipeline and supply chain."""
    path = _resolve_path(path)
    result = scan_directory(path, scan_types=["pipeline"])

    if compliance:
        comp = check_compliance(path, framework=compliance)
        console.print(
            Panel(
                json.dumps(comp, indent=2),
                title=f"{compliance.upper()} Compliance",
                border_style="green",
            )
        )

    if json_output:
        console.print(result.model_dump_json(indent=2))
    else:
        console.print(
            Panel(
                generate_report(result, fmt="text"),
                title="Pipeline Audit",
                border_style="green",
            )
        )


@app.command()
def manifest(
    path: Path = typer.Argument(..., help="Path to model directory"),
    verify: bool = typer.Option(False, "--verify", "-v", help="Verify against existing manifest"),
    output: Path = typer.Option(None, "--output", "-o", help="Output manifest path"),
):
    """Generate or verify a weight integrity manifest."""
    path = _resolve_path(path)

    if verify:
        manifest_file = path / "aishield_manifest.json"
        if not manifest_file.exists():
            manifest_file = path / "weight_manifest.json"
        if not manifest_file.exists():
            console.print("[red]Error:[/] No manifest found. Generate one first.")
            raise typer.Exit(1)

        manifest = json.loads(manifest_file.read_text())
        issues = verify_manifest(path, manifest)
        if issues:
            console.print("[red]Weight integrity verification FAILED:[/]")
            for issue in issues:
                console.print(f"  [!] {issue}")
            raise typer.Exit(1)
        else:
            console.print("[green]Weight integrity verification PASSED.[/]")
    else:
        m = generate_manifest(path)
        manifest_path = save_manifest(
            path, m, filename=output.name if output else "aishield_manifest.json"
        )
        console.print(f"[green]Manifest written to {manifest_path}[/]")
        console.print(f"  Files: {len(m['files'])}")
        console.print(f"  Integrity hash: {m['integrity_hash'][:16]}...")


@app.command()
def supply_chain(
    path: Path = typer.Argument(..., help="Path to model directory"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
):
    """Analyze model supply chain from base model to deployment."""
    path = _resolve_path(path)

    report = generate_supply_chain_report(path)

    if json_output:
        console.print(json.dumps(report, indent=2))
    else:
        lines = [
            "## Supply Chain Analysis",
            "",
            f"**Model:** {report['model_path']}",
            f"**Trust Score:** {report['trust_score']}/100",
            "",
        ]
        for stage, status in report["supply_chain_stages"].items():
            lines.append(f"  {stage}: {status}")
        lines.append("")

        if report["findings"]:
            lines.append("**Findings:**")
            for f in report["findings"]:
                lines.append(f"  [{f['severity']}] {f['check']}: {f['detail']}")

        console.print(Panel("\n".join(lines), title="Supply Chain Report", border_style="blue"))


def main():
    """Entry point for the aishield CLI."""
    app()


if __name__ == "__main__":
    main()
