"""Cryptographic utilities for hashing, fingerprinting, and integrity verification."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        path: Path to the file.

    Returns:
        Hex digest string.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes.

    Args:
        data: Input bytes.

    Returns:
        Hex digest string.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_string(text: str) -> str:
    """Compute SHA-256 hash of a string.

    Args:
        text: Input string.

    Returns:
        Hex digest string.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_combined_hash(file_hashes: list[str]) -> str:
    """Compute a combined integrity hash from a list of file hashes.

    Args:
        file_hashes: List of SHA-256 hex digests (sorted order expected).

    Returns:
        Combined SHA-256 hex digest.
    """
    h = hashlib.sha256()
    for fh in sorted(file_hashes):
        h.update(fh.encode("utf-8"))
    return h.hexdigest()


def hash_directory(
    path: Path,
    patterns: list[str] | None = None,
) -> dict[str, Any]:
    """Hash all matching files in a directory.

    Args:
        path: Directory to scan.
        patterns: Glob patterns to match (default: ["*"]).

    Returns:
        Dict with file entries and combined integrity_hash.
    """
    if patterns is None:
        patterns = ["*"]

    entries: list[dict[str, Any]] = []
    hashes: list[str] = []

    for pattern in sorted(patterns):
        for f in sorted(path.glob(pattern)):
            if f.is_file():
                file_hash = sha256_file(f)
                entries.append({
                    "path": f.name,
                    "size_bytes": f.stat().st_size,
                    "sha256": file_hash,
                })
                hashes.append(file_hash)

    return {
        "directory": str(path.resolve()),
        "files": entries,
        "integrity_hash": compute_combined_hash(hashes) if hashes else "",
    }


def verify_directory_hash(
    path: Path,
    manifest: dict[str, Any],
) -> list[str]:
    """Verify directory files against a stored manifest.

    Args:
        path: Directory to verify.
        manifest: Manifest dict from hash_directory().

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

    if manifest.get("integrity_hash"):
        actual_total = compute_combined_hash(hashes)
        if actual_total != manifest["integrity_hash"]:
            issues.append("Total integrity hash mismatch — files may have been modified")

    return issues
