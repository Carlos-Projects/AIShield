"""Tests for weight manifest."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.utils.crypto import sha256_file
from aishield.weights.manifest import generate_manifest, save_manifest, verify_manifest


class TestGenerateManifest:
    def test_generate_manifest(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        manifest = generate_manifest(tmp_path)
        assert len(manifest["files"]) == 1
        assert manifest["files"][0]["path"] == "model.safetensors"
        assert manifest["integrity_hash"] != ""

    def test_manifest_multiple_files(self, tmp_path: Path):
        (tmp_path / "model-00001.safetensors").write_bytes(b"part1")
        (tmp_path / "model-00002.safetensors").write_bytes(b"part2")
        manifest = generate_manifest(tmp_path)
        assert len(manifest["files"]) == 2

    def test_manifest_no_files(self, tmp_path: Path):
        manifest = generate_manifest(tmp_path)
        assert manifest["files"] == []
        assert manifest["integrity_hash"] == ""

    def test_manifest_hash_correct(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"test data")
        manifest = generate_manifest(tmp_path)
        expected = sha256_file(tmp_path / "model.safetensors")
        assert manifest["files"][0]["sha256"] == expected


class TestVerifyManifest:
    def test_verify_pass(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        manifest = generate_manifest(tmp_path)
        issues = verify_manifest(tmp_path, manifest)
        assert issues == []

    def test_verify_missing_file(self, tmp_path: Path):
        manifest = {
            "files": [{"path": "missing.safetensors", "sha256": "abc"}],
            "integrity_hash": "xyz",
        }
        issues = verify_manifest(tmp_path, manifest)
        assert len(issues) > 0
        assert "Missing file" in issues[0]

    def test_verify_tampered(self, tmp_path: Path):
        (tmp_path / "model.safetensors").write_bytes(b"original")
        manifest = generate_manifest(tmp_path)
        (tmp_path / "model.safetensors").write_bytes(b"tampered")
        issues = verify_manifest(tmp_path, manifest)
        assert len(issues) > 0
        assert "Hash mismatch" in issues[0]

    def test_verify_empty_manifest(self, tmp_path: Path):
        manifest = {"files": [], "integrity_hash": ""}
        issues = verify_manifest(tmp_path, manifest)
        assert issues == []


class TestSaveManifest:
    def test_save_manifest(self, tmp_path: Path):
        manifest = {"files": [], "integrity_hash": "abc"}
        path = save_manifest(tmp_path, manifest)
        assert path.exists()
        saved = json.loads(path.read_text())
        assert saved == manifest

    def test_save_custom_filename(self, tmp_path: Path):
        manifest = {"files": [], "integrity_hash": "abc"}
        path = save_manifest(tmp_path, manifest, filename="custom.json")
        assert path.name == "custom.json"
