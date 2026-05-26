"""Tests for weight integrity checker."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.utils.crypto import compute_combined_hash, sha256_file
from aishield.weights.integrity_checker import check_weight_integrity


class TestCheckWeightIntegrity:
    def test_missing_manifest(self, tmp_path: Path):
        findings = check_weight_integrity(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_weight_manifest"]
        assert len(missing) > 0

    def test_valid_manifest(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"fake weights data")
        file_hash = sha256_file(tmp_path / "model.safetensors")
        combined = compute_combined_hash([file_hash])
        manifest = {
            "files": [{"path": "model.safetensors", "sha256": file_hash}],
            "integrity_hash": combined,
        }
        (tmp_path / "aishield_manifest.json").write_text(json.dumps(manifest))
        findings = check_weight_integrity(tmp_path)
        failed = [f for f in findings if f["check"] == "weight_integrity_failed"]
        assert len(failed) == 0

    def test_tampered_weights(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"original")
        original_hash = sha256_file(tmp_path / "model.safetensors")
        manifest = {
            "files": [{"path": "model.safetensors", "sha256": original_hash}],
            "integrity_hash": original_hash,
        }
        (tmp_path / "aishield_manifest.json").write_text(json.dumps(manifest))
        (tmp_path / "model.safetensors").write_bytes(b"tampered")
        findings = check_weight_integrity(tmp_path)
        failed = [f for f in findings if f["check"] == "weight_integrity_failed"]
        assert len(failed) > 0
        assert failed[0]["severity"] == "critical"

    def test_missing_weight_file(self, tmp_path: Path):
        manifest = {
            "files": [{"path": "missing.safetensors", "sha256": "abc"}],
            "integrity_hash": "xyz",
        }
        (tmp_path / "aishield_manifest.json").write_text(json.dumps(manifest))
        findings = check_weight_integrity(tmp_path)
        failed = [f for f in findings if f["check"] == "weight_integrity_failed"]
        assert len(failed) > 0

    def test_no_weight_files(self, tmp_path: Path):
        findings = check_weight_integrity(tmp_path)
        no_weights = [f for f in findings if f["check"] == "no_weight_files"]
        assert len(no_weights) > 0

    def test_unsafe_weight_format(self, tmp_path: Path):
        (tmp_path / "pytorch_model.bin").write_bytes(b"fake")
        findings = check_weight_integrity(tmp_path)
        unsafe = [f for f in findings if f["check"] == "unsafe_weight_format"]
        assert len(unsafe) > 0

    def test_suspicious_weight_filename(self, tmp_path: Path):
        (tmp_path / "model_modified.safetensors").write_bytes(b"fake")
        findings = check_weight_integrity(tmp_path)
        suspicious = [f for f in findings if f["check"] == "suspicious_weight_filename"]
        assert len(suspicious) > 0

    def test_small_model_size(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"x" * 1000)
        findings = check_weight_integrity(tmp_path)
        small = [f for f in findings if f["check"] == "small_model_size"]
        assert len(small) > 0

    def test_corrupt_manifest(self, tmp_path: Path):
        (tmp_path / "aishield_manifest.json").write_text("not json {{{")
        findings = check_weight_integrity(tmp_path)
        corrupt = [f for f in findings if f["check"] == "corrupt_manifest"]
        assert len(corrupt) > 0

    def test_safetensors_preferred(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"safe weights")
        findings = check_weight_integrity(tmp_path)
        unsafe = [f for f in findings if f["check"] == "unsafe_weight_format"]
        assert len(unsafe) == 0
