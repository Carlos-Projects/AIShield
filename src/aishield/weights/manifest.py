"""Weight manifest generation and verification.

Generates SHA-256 manifests for model weights (compatible with
reverse-abliterate patterns) and verifies integrity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aishield.utils.crypto import compute_combined_hash, sha256_file


def generate_manifest(path: Path) -> dict[str, Any]:
    """Generate a SHA-256 weight integrity manifest.

    Compatible with reverse-abliterate manifest format.

    Args:
        path: Path to model directory.

    Returns:
        Manifest dict with files list and integrity_hash.
    """
    manifest: dict[str, Any] = {
        "model_path": str(path.resolve()),
        "files": [],
        "integrity_hash": "",
    }

    hashes: list[str] = []
    weight_patterns = ["*.safetensors", "*.bin", "*.pth", "*.ckpt", "*.gguf"]

    for pattern in weight_patterns:
        for f in sorted(path.glob(pattern)):
            if f.is_file():
                file_hash = sha256_file(f)
                manifest["files"].append({
                    "path": f.name,
                    "size_bytes": f.stat().st_size,
                    "sha256": file_hash,
                })
                hashes.append(file_hash)

    manifest["integrity_hash"] = compute_combined_hash(hashes) if hashes else ""
    return manifest


def verify_manifest(path: Path, manifest: dict[str, Any]) -> list[str]:
    """Verify model weights against a manifest.

    Args:
        path: Path to model directory.
        manifest: Manifest dict from generate_manifest().

    Returns:
        List of issue descriptions. Empty means verified.
    """
    issues: list[str] = []
    hashes: list[str] = []

    for entry in manifest.get("files", []):
        f = path / entry["path"]
        if not f.exists():
            issues.append(f"Missing file: {entry['path']}")
            continue
        actual = sha256_file(f)
        if actual != entry["sha256"]:
            issues.append(f"Hash mismatch: {entry['path']}")
        hashes.append(actual)

    if manifest.get("integrity_hash") and hashes:
        actual_total = compute_combined_hash(hashes)
        if actual_total != manifest["integrity_hash"]:
            issues.append("Total integrity hash mismatch — weights may have been modified")

    return issues


def save_manifest(path: Path, manifest: dict[str, Any], filename: str = "aishield_manifest.json") -> Path:
    """Save manifest to file.

    Args:
        path: Directory to save manifest in.
        manifest: Manifest dict.
        filename: Manifest filename.

    Returns:
        Path to saved manifest file.
    """
    manifest_path = path / filename
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest_path
