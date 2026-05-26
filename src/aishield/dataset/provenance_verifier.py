"""Dataset provenance verification.

Verifies the chain of custody and source authenticity of fine-tuning
datasets using checksums, source metadata, and origin validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def verify_provenance(path: Path) -> list[dict[str, Any]]:
    """Verify dataset provenance and chain of custody.

    Checks for provenance metadata files, dataset cards, source URLs,
    and checksum manifests.

    Args:
        path: Path to model or dataset directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    _check_provenance_metadata(path, findings)
    _check_dataset_card(path, findings)
    _check_checksum_manifest(path, findings)
    _check_source_urls(path, findings)

    return findings


def _check_provenance_metadata(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for provenance metadata file."""
    meta_files = ["provenance.json", "dataset_provenance.json", "chain_of_custody.json"]
    found = False

    for mf in meta_files:
        f = path / mf
        if f.exists():
            found = True
            try:
                meta = json.loads(f.read_text())
                required_fields = ["source", "created_at", "checksum"]
                missing = [rf for rf in required_fields if rf not in meta]
                if missing:
                    findings.append({
                        "severity": "high",
                        "check": "incomplete_provenance",
                        "detail": f"Provenance metadata missing required fields: {', '.join(missing)}",
                        "evidence": {"file": mf, "missing_fields": missing},
                        "recommendation": "Add complete provenance metadata including source, timestamp, and checksum",
                    })
            except (json.JSONDecodeError, OSError):
                findings.append({
                    "severity": "high",
                    "check": "corrupt_provenance",
                    "detail": f"Provenance file {mf} exists but is unreadable",
                    "evidence": {"file": mf},
                })

    if not found:
        findings.append({
            "severity": "medium",
            "check": "missing_provenance",
            "detail": "No provenance metadata file found — dataset origin cannot be verified",
            "evidence": {"searched": meta_files},
            "recommendation": "Create a provenance.json file documenting dataset source, creation date, and checksums",
        })


def _check_dataset_card(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for dataset card (README.md or dataset_card.yaml)."""
    card_files = ["README.md", "dataset_card.yaml", "dataset_card.yml", "DATASHEET.md"]
    found = any((path / cf).exists() for cf in card_files)

    if not found:
        findings.append({
            "severity": "low",
            "check": "missing_dataset_card",
            "detail": "No dataset card found — documentation of dataset contents and limitations is missing",
            "evidence": {"searched": card_files},
            "recommendation": "Add a dataset card documenting source, preprocessing, known limitations, and intended use",
        })


def _check_checksum_manifest(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for checksum manifest of dataset files."""
    manifest_files = ["checksums.sha256", "checksums.md5", "MANIFEST"]
    found = False

    for mf in manifest_files:
        f = path / mf
        if f.exists():
            found = True
            break

    if not found:
        data_files = list(path.glob("*.json")) + list(path.glob("*.jsonl")) + list(path.glob("*.csv"))
        if data_files:
            findings.append({
                "severity": "medium",
                "check": "missing_checksum_manifest",
                "detail": f"No checksum manifest found for {len(data_files)} dataset file(s)",
                "evidence": {"data_files": len(data_files)},
                "recommendation": "Generate a checksums.sha256 file for all dataset files",
            })


def _check_source_urls(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for source URL references in metadata."""
    for meta_file in path.glob("*.json"):
        try:
            data = json.loads(meta_file.read_text())
            if isinstance(data, dict):
                _check_dict_for_sources(data, meta_file.name, findings)
        except (json.JSONDecodeError, OSError):
            continue


def _check_dict_for_sources(data: dict, filename: str, findings: list[dict[str, Any]]) -> None:
    """Recursively check dict for source URL fields."""
    source_keys = ["source_url", "url", "origin", "dataset_url", "huggingface_url"]
    for key in source_keys:
        if data.get(key):
            url = str(data[key])
            if not url.startswith(("https://", "http://")):
                findings.append({
                    "severity": "low",
                    "check": "invalid_source_url",
                    "detail": f"Source URL in {filename} is not a valid HTTP(S) URL: {url}",
                    "evidence": {"file": filename, "key": key, "url": url},
                })
            return

    for value in data.values():
        if isinstance(value, dict):
            _check_dict_for_sources(value, filename, findings)
