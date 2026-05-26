"""Model weight integrity checking.

Verifies integrity of model weight files using SHA-256 manifests,
detects tampering, and checks for suspicious weight patterns.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aishield.utils.crypto import compute_combined_hash, sha256_file


def check_weight_integrity(path: Path) -> list[dict[str, Any]]:
    """Check model weight files for integrity issues.

    Verifies against existing manifests, checks for missing files,
    and detects suspicious weight file characteristics.

    Args:
        path: Path to model directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    _check_manifest_verification(path, findings)
    _check_weight_files(path, findings)
    _check_weight_naming(path, findings)
    _check_weight_sizes(path, findings)

    return findings


def _check_manifest_verification(path: Path, findings: list[dict[str, Any]]) -> None:
    """Verify weights against existing manifest."""
    manifest_file = path / "weight_manifest.json"
    if not manifest_file.exists():
        # Check for aishield manifest
        manifest_file = path / "aishield_manifest.json"

    if not manifest_file.exists():
        findings.append({
            "severity": "medium",
            "check": "missing_weight_manifest",
            "detail": "No weight integrity manifest found — cannot verify weight authenticity",
            "evidence": {"searched": ["weight_manifest.json", "aishield_manifest.json"]},
            "recommendation": "Generate a weight manifest using 'aishield manifest' before deployment",
        })
        return

    try:
        manifest = json.loads(manifest_file.read_text())
    except (json.JSONDecodeError, OSError):
        findings.append({
            "severity": "high",
            "check": "corrupt_manifest",
            "detail": f"Weight manifest {manifest_file.name} is unreadable",
            "evidence": {"file": str(manifest_file)},
        })
        return

    # Verify each file
    issues: list[str] = []
    hashes: list[str] = []

    for entry in manifest.get("files", []):
        f = path / entry["path"]
        if not f.exists():
            issues.append(f"Missing: {entry['path']}")
            continue
        actual = sha256_file(f)
        if actual != entry["sha256"]:
            issues.append(f"Hash mismatch: {entry['path']}")
        hashes.append(actual)

    # Only check combined hash if we verified all files successfully
    if manifest.get("integrity_hash") and hashes and not issues:
        actual_total = compute_combined_hash(hashes)
        if actual_total != manifest["integrity_hash"]:
            issues.append("Total integrity hash mismatch")

    if issues:
        findings.append({
            "severity": "critical",
            "check": "weight_integrity_failed",
            "detail": f"Weight integrity verification failed: {'; '.join(issues)}",
            "evidence": {"issues": issues, "manifest": str(manifest_file)},
            "recommendation": "Weights have been modified — do not use this model until source is verified",
        })


def _check_weight_files(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for presence of weight files."""
    safetensors = list(path.glob("*.safetensors"))
    pth_files = list(path.glob("*.pth"))
    bin_files = list(path.glob("*.bin"))

    weight_files = safetensors + pth_files + bin_files

    if not weight_files:
        findings.append({
            "severity": "high",
            "check": "no_weight_files",
            "detail": "No model weight files found (.safetensors, .pth, .bin)",
            "evidence": {"path": str(path)},
            "recommendation": "Verify model directory contains weight files",
        })
        return

    # Prefer safetensors over pickle formats
    if not safetensors and (pth_files or bin_files):
        findings.append({
            "severity": "medium",
            "check": "unsafe_weight_format",
            "detail": f"Model uses pickle-based weights ({len(pth_files)} .pth, {len(bin_files)} .bin) — vulnerable to deserialization attacks",
            "evidence": {"pth": len(pth_files), "bin": len(bin_files)},
            "recommendation": "Convert to .safetensors format for secure weight loading",
        })


def _check_weight_naming(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check weight file naming for suspicious patterns."""
    for wf in path.glob("*.safetensors"):
        name = wf.name.lower()
        suspicious_patterns = [
            ("modified", "Filename suggests modified weights"),
            ("patched", "Filename suggests patched weights"),
            ("injected", "Filename suggests injected weights"),
            ("backdoor", "Filename suggests backdoor weights"),
            ("poison", "Filename suggests poisoned weights"),
        ]
        for pattern, detail in suspicious_patterns:
            if pattern in name:
                findings.append({
                    "severity": "critical",
                    "check": "suspicious_weight_filename",
                    "detail": f"{detail}: {wf.name}",
                    "evidence": {"file": wf.name, "pattern": pattern},
                    "recommendation": "Verify weight file source — filename suggests tampering",
                })


def _check_weight_sizes(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check weight file sizes for anomalies."""
    weight_files = list(path.glob("*.safetensors"))
    if not weight_files:
        return

    sizes = [f.stat().st_size for f in weight_files]
    total_size = sum(sizes)

    # Check for unusually small total size (may indicate stripped model)
    if total_size < 100_000_000:  # 100MB
        findings.append({
            "severity": "medium",
            "check": "small_model_size",
            "detail": f"Total model size is {total_size / 1e6:.1f}MB — may be a distilled or stripped model",
            "evidence": {"total_size_mb": round(total_size / 1e6, 1), "file_count": len(weight_files)},
            "recommendation": "Verify model size matches expected values for the claimed architecture",
        })

    # Check for single very large file
    for wf in weight_files:
        size = wf.stat().st_size
        if size > 50_000_000_000:  # 50GB
            findings.append({
                "severity": "info",
                "check": "large_weight_file",
                "detail": f"Weight file {wf.name} is very large ({size / 1e9:.1f}GB)",
                "evidence": {"file": wf.name, "size_gb": round(size / 1e9, 1)},
            })
