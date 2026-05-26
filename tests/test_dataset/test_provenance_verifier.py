"""Tests for dataset provenance verifier."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.dataset.provenance_verifier import verify_provenance


class TestVerifyProvenance:
    def test_missing_provenance(self, tmp_path: Path):
        findings = verify_provenance(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_provenance"]
        assert len(missing) > 0
        assert missing[0]["severity"] == "medium"

    def test_valid_provenance(self, tmp_path: Path):
        meta = {
            "source": "https://example.com/dataset",
            "created_at": "2025-01-01",
            "checksum": "abc123",
        }
        (tmp_path / "provenance.json").write_text(json.dumps(meta))
        findings = verify_provenance(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_provenance"]
        assert len(missing) == 0

    def test_incomplete_provenance(self, tmp_path: Path):
        meta = {"source": "https://example.com"}
        (tmp_path / "provenance.json").write_text(json.dumps(meta))
        findings = verify_provenance(tmp_path)
        incomplete = [f for f in findings if f["check"] == "incomplete_provenance"]
        assert len(incomplete) > 0

    def test_missing_dataset_card(self, tmp_path: Path):
        findings = verify_provenance(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_dataset_card"]
        assert len(missing) > 0

    def test_dataset_card_present(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Dataset")
        findings = verify_provenance(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_dataset_card"]
        assert len(missing) == 0

    def test_missing_checksum_manifest(self, tmp_path: Path):
        (tmp_path / "data.json").write_text("[]")
        findings = verify_provenance(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_checksum_manifest"]
        assert len(missing) > 0

    def test_checksum_manifest_present(self, tmp_path: Path):
        (tmp_path / "data.json").write_text("[]")
        (tmp_path / "checksums.sha256").write_text("abc123  data.json")
        findings = verify_provenance(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_checksum_manifest"]
        assert len(missing) == 0

    def test_corrupt_provenance(self, tmp_path: Path):
        (tmp_path / "provenance.json").write_text("not valid json {{{")
        findings = verify_provenance(tmp_path)
        corrupt = [f for f in findings if f["check"] == "corrupt_provenance"]
        assert len(corrupt) > 0

    def test_invalid_source_url(self, tmp_path: Path):
        meta = {"source_url": "not-a-url", "created_at": "2025-01-01", "checksum": "abc"}
        (tmp_path / "provenance.json").write_text(json.dumps(meta))
        findings = verify_provenance(tmp_path)
        invalid = [f for f in findings if f["check"] == "invalid_source_url"]
        assert len(invalid) > 0

    def test_valid_source_url(self, tmp_path: Path):
        meta = {"source_url": "https://huggingface.co/datasets/example", "created_at": "2025-01-01", "checksum": "abc"}
        (tmp_path / "provenance.json").write_text(json.dumps(meta))
        findings = verify_provenance(tmp_path)
        invalid = [f for f in findings if f["check"] == "invalid_source_url"]
        assert len(invalid) == 0
