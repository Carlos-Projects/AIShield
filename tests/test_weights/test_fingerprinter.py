"""Tests for weight fingerprinter."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.weights.fingerprinter import fingerprint_model, generate_fingerprint


class TestFingerprintModel:
    def test_fingerprint_generated(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        findings = fingerprint_model(tmp_path)
        fp_findings = [f for f in findings if f["check"] == "model_fingerprint"]
        assert len(fp_findings) > 0
        assert fp_findings[0]["evidence"]["fingerprint"] != ""

    def test_fingerprint_match(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        generate_fingerprint(tmp_path)

        findings = fingerprint_model(tmp_path)
        mismatch = [f for f in findings if f["check"] == "fingerprint_mismatch"]
        assert len(mismatch) == 0

    def test_fingerprint_mismatch(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"original")
        stored_fp = {
            "fingerprint": "abc123def456",
            "file_count": 1,
            "files": [{"name": "model.safetensors", "sha256": "fake"}],
        }
        (tmp_path / "model_fingerprint.json").write_text(json.dumps(stored_fp))

        findings = fingerprint_model(tmp_path)
        mismatch = [f for f in findings if f["check"] == "fingerprint_mismatch"]
        assert len(mismatch) > 0
        assert mismatch[0]["severity"] == "critical"

    def test_no_weight_files(self, tmp_path: Path):
        findings = fingerprint_model(tmp_path)
        assert findings == []

    def test_corrupt_fingerprint_file(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        (tmp_path / "model_fingerprint.json").write_text("not json {{{")
        findings = fingerprint_model(tmp_path)
        corrupt = [f for f in findings if f["check"] == "corrupt_fingerprint"]
        assert len(corrupt) > 0


class TestGenerateFingerprint:
    def test_save_fingerprint(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        fp = generate_fingerprint(tmp_path)
        assert "fingerprint" in fp
        assert fp["file_count"] == 1
        assert (tmp_path / "model_fingerprint.json").exists()

    def test_fingerprint_deterministic(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        fp1 = generate_fingerprint(tmp_path)
        fp2 = generate_fingerprint(tmp_path)
        assert fp1["fingerprint"] == fp2["fingerprint"]
