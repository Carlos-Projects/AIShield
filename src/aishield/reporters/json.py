"""JSON reporter.

Exports scan results as structured JSON.
"""

from __future__ import annotations

from pathlib import Path

from aishield.scanner import ScanResult


def render_json_report(result: ScanResult, indent: int = 2) -> str:
    """Render scan result as JSON.

    Args:
        result: ScanResult to render.
        indent: JSON indentation level.

    Returns:
        JSON string.
    """
    return result.model_dump_json(indent=indent)


def save_json_report(result: ScanResult, output_path: str) -> None:
    """Save scan result as JSON file.

    Args:
        result: ScanResult to save.
        output_path: Path to output file.
    """
    Path(output_path).write_text(render_json_report(result))
