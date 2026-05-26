"""Dataset statistical analysis.

Computes statistical profiles of datasets to detect anomalies
that may indicate poisoning or data manipulation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


def analyze_dataset_stats(path: Path) -> list[dict[str, Any]]:
    """Analyze dataset statistics for anomaly detection.

    Computes token length distributions, vocabulary entropy,
    and other statistical measures to detect outliers.

    Args:
        path: Path to model or dataset directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    data_files = list(path.glob("*.json")) + list(path.glob("*.jsonl"))
    for df in data_files:
        if df.is_file():
            _analyze_file_stats(df, findings)

    return findings


def _analyze_file_stats(filepath: Path, findings: list[dict[str, Any]]) -> None:
    """Analyze statistical properties of a dataset file."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        if filepath.suffix == ".jsonl":
            entries = [json.loads(line) for line in content.strip().split("\n") if line.strip()]
        else:
            data = json.loads(content)
            entries = data if isinstance(data, list) else [data]
    except (json.JSONDecodeError, ValueError, OSError):
        return

    if not entries:
        return

    # Analyze content length distribution
    lengths = []
    for entry in entries:
        if isinstance(entry, dict):
            text = entry.get("content", entry.get("text", ""))
            if isinstance(text, str):
                lengths.append(len(text))

    if len(lengths) < 10:
        return

    mean_len = sum(lengths) / len(lengths)
    variance = sum((length - mean_len) ** 2 for length in lengths) / len(lengths)
    std_dev = math.sqrt(variance) if variance > 0 else 0

    # Detect outliers (entries > 3 standard deviations from mean)
    if std_dev > 0:
        outliers_count = sum(1 for length in lengths if abs(length - mean_len) > 3 * std_dev)
        outlier_ratio = outliers_count / len(lengths)

        if outlier_ratio > 0.05:
            findings.append(
                {
                    "severity": "medium",
                    "check": "length_anomaly",
                    "detail": f"{outlier_ratio:.1%} of entries in {filepath.name} have anomalous lengths (>3 sigma from mean)",
                    "evidence": {
                        "file": filepath.name,
                        "total_entries": len(lengths),
                        "outliers": outliers_count,
                        "mean_length": round(mean_len, 1),
                        "std_dev": round(std_dev, 1),
                    },
                    "recommendation": "Review outlier entries — may indicate injected data with unusual lengths",
                }
            )

    # Check for very short entries (potential trigger injections)
    short_entries = sum(1 for length in lengths if length < 10)
    if short_entries > len(lengths) * 0.05:
        findings.append(
            {
                "severity": "low",
                "check": "short_entries",
                "detail": f"{short_entries} very short entries (<10 chars) in {filepath.name} — may contain trigger tokens",
                "evidence": {
                    "file": filepath.name,
                    "short_count": short_entries,
                    "total": len(lengths),
                },
                "recommendation": "Review short entries for hidden trigger patterns",
            }
        )

    # Check for entropy anomalies in text content
    texts = []
    for entry in entries:
        if isinstance(entry, dict):
            text = entry.get("content", entry.get("text", ""))
            if isinstance(text, str) and len(text) > 0:
                texts.append(text)

    if texts:
        entropies = [_shannon_entropy(t) for t in texts]
        mean_entropy = sum(entropies) / len(entropies)

        # High entropy may indicate encoded/obfuscated content
        high_entropy = sum(1 for e in entropies if e > 5.5)
        if high_entropy > len(entropies) * 0.1:
            findings.append(
                {
                    "severity": "medium",
                    "check": "high_entropy_content",
                    "detail": f"{high_entropy} entries in {filepath.name} have unusually high Shannon entropy (>5.5)",
                    "evidence": {
                        "file": filepath.name,
                        "high_entropy_count": high_entropy,
                        "mean_entropy": round(mean_entropy, 3),
                    },
                    "recommendation": "Review high-entropy entries — may contain encoded payloads or obfuscated triggers",
                }
            )


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string.

    Args:
        text: Input string.

    Returns:
        Entropy value in bits per character.
    """
    if not text:
        return 0.0

    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1

    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy
