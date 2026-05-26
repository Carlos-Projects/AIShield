"""Model fingerprinting.

Creates unique fingerprints of model weights for tamper detection
and model identity verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aishield.utils.crypto import compute_combined_hash, sha256_file


def fingerprint_model(path: Path) -> list[dict[str, Any]]:
    """Generate and verify model fingerprints.

    Creates a unique fingerprint from model weight files that can
    be used to detect modifications or verify model identity.

    Args:
        path: Path to model directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    _generate_fingerprint(path, findings)
    _check_fingerprint_match(path, findings)

    return findings


def _generate_fingerprint(path: Path, findings: list[dict[str, Any]]) -> None:
    """Generate model fingerprint and compare with stored fingerprint."""
    weight_files = sorted(path.glob("*.safetensors"))
    if not weight_files:
        weight_files = sorted(path.glob("*.bin"))
    if not weight_files:
        weight_files = sorted(path.glob("*.pth"))

    if not weight_files:
        return

    file_hashes = []
    for wf in weight_files:
        file_hashes.append(sha256_file(wf))

    fingerprint = compute_combined_hash(file_hashes)
    model_info = {
        "file_count": len(weight_files),
        "total_size": sum(f.stat().st_size for f in weight_files),
        "files": [
            {"name": f.name, "sha256": h} for f, h in zip(weight_files, file_hashes, strict=False)
        ],
    }

    findings.append(
        {
            "severity": "info",
            "check": "model_fingerprint",
            "detail": f"Model fingerprint: {fingerprint[:16]}... ({len(weight_files)} files)",
            "evidence": {"fingerprint": fingerprint, "model_info": model_info},
            "recommendation": "",
        }
    )


def _check_fingerprint_match(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check if current fingerprint matches stored fingerprint."""
    fingerprint_file = path / "model_fingerprint.json"
    if not fingerprint_file.exists():
        return

    try:
        stored = json.loads(fingerprint_file.read_text())
    except (json.JSONDecodeError, OSError):
        findings.append(
            {
                "severity": "high",
                "check": "corrupt_fingerprint",
                "detail": "Model fingerprint file is unreadable",
                "evidence": {"file": str(fingerprint_file)},
            }
        )
        return

    stored_fp = stored.get("fingerprint", "")
    if not stored_fp:
        return

    # Compute current fingerprint
    weight_files = sorted(path.glob("*.safetensors"))
    if not weight_files:
        weight_files = sorted(path.glob("*.bin"))

    if not weight_files:
        return

    file_hashes = [sha256_file(wf) for wf in weight_files]
    current_fp = compute_combined_hash(file_hashes)

    if current_fp != stored_fp:
        findings.append(
            {
                "severity": "critical",
                "check": "fingerprint_mismatch",
                "detail": "Model fingerprint does not match stored fingerprint — weights have been modified",
                "evidence": {
                    "stored_fingerprint": stored_fp[:16],
                    "current_fingerprint": current_fp[:16],
                },
                "recommendation": "Model weights have changed since fingerprint was recorded — verify source",
            }
        )


def generate_fingerprint(path: Path) -> dict[str, Any]:
    """Generate a model fingerprint and save it.

    Args:
        path: Path to model directory.

    Returns:
        Fingerprint dict.
    """
    weight_files = sorted(path.glob("*.safetensors"))
    if not weight_files:
        weight_files = sorted(path.glob("*.bin"))

    file_hashes = []
    for wf in weight_files:
        file_hashes.append(sha256_file(wf))

    fingerprint = compute_combined_hash(file_hashes)

    result = {
        "fingerprint": fingerprint,
        "file_count": len(weight_files),
        "files": [
            {"name": f.name, "sha256": h} for f, h in zip(weight_files, file_hashes, strict=False)
        ],
    }

    fingerprint_file = path / "model_fingerprint.json"
    fingerprint_file.write_text(json.dumps(result, indent=2))

    return result
