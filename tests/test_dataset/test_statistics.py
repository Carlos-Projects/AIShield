"""Tests for dataset statistics."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.dataset.statistics import _shannon_entropy, analyze_dataset_stats


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_uniform_string(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        e = _shannon_entropy("abcdef")
        assert e > 0

    def test_deterministic(self):
        e1 = _shannon_entropy("hello world")
        e2 = _shannon_entropy("hello world")
        assert e1 == e2


class TestAnalyzeDatasetStats:
    def test_no_data_files(self, tmp_path: Path):
        findings = analyze_dataset_stats(tmp_path)
        assert findings == []

    def test_normal_distribution(self, tmp_path: Path):
        dataset = [{"content": "hello world " * 10} for _ in range(50)]
        (tmp_path / "normal.json").write_text(json.dumps(dataset))
        findings = analyze_dataset_stats(tmp_path)
        anomalies = [f for f in findings if f["check"] == "length_anomaly"]
        assert len(anomalies) == 0

    def test_length_anomaly(self, tmp_path: Path):
        dataset = [{"content": "short text"} for _ in range(50)]
        dataset.append({"content": "x" * 50000})
        dataset.append({"content": "y" * 60000})
        dataset.append({"content": "z" * 70000})
        dataset.append({"content": "w" * 80000})
        (tmp_path / "anomalous.json").write_text(json.dumps(dataset))
        findings = analyze_dataset_stats(tmp_path)
        anomalies = [f for f in findings if f["check"] == "length_anomaly"]
        assert len(anomalies) > 0

    def test_short_entries(self, tmp_path: Path):
        dataset = [{"content": "x"} for _ in range(50)]
        dataset.extend([{"content": "normal text here"} for _ in range(10)])
        (tmp_path / "short.json").write_text(json.dumps(dataset))
        findings = analyze_dataset_stats(tmp_path)
        short = [f for f in findings if f["check"] == "short_entries"]
        assert len(short) > 0

    def test_high_entropy_content(self, tmp_path: Path):
        high_entropy = "".join(chr(32 + (i * 37) % 95) for i in range(200))
        dataset = [{"content": high_entropy} for _ in range(15)]
        dataset.extend([{"content": "normal text here"} for _ in range(5)])
        (tmp_path / "entropy.json").write_text(json.dumps(dataset))
        findings = analyze_dataset_stats(tmp_path)
        high = [f for f in findings if f["check"] == "high_entropy_content"]
        assert len(high) > 0

    def test_jsonl_format(self, tmp_path: Path):
        lines = [json.dumps({"content": "hello world"}) for _ in range(20)]
        (tmp_path / "data.jsonl").write_text("\n".join(lines))
        findings = analyze_dataset_stats(tmp_path)
        assert isinstance(findings, list)

    def test_empty_dataset(self, tmp_path: Path):
        (tmp_path / "empty.json").write_text("[]")
        findings = analyze_dataset_stats(tmp_path)
        assert findings == []

    def test_invalid_json(self, tmp_path: Path):
        (tmp_path / "bad.json").write_text("not json")
        findings = analyze_dataset_stats(tmp_path)
        assert findings == []
