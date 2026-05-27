"""Tests for path redaction and other scanner enhancements."""

from __future__ import annotations

from pathlib import Path

import pytest

from aishield.scanner import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_OUTLIER_THRESHOLD,
    DEFAULT_TIMEOUT,
    MITRE_ATLAS_MAP,
    Finding,
    FindingCategory,
    Severity,
    redact_paths_in_finding,
    scan_directory,
)
from aishield.utils.file_io import read_text_safe, stream_lines, utf8_validate_file


class TestMitreAtlasMap:
    def test_common_checks_mapped(self):
        assert "poisoning_trigger_pattern" in MITRE_ATLAS_MAP
        assert "weight_integrity_failed" in MITRE_ATLAS_MAP
        assert "hardcoded_credential" in MITRE_ATLAS_MAP
        assert "unknown_base_model" in MITRE_ATLAS_MAP

    def test_mapping_format(self):
        for check, mapping in MITRE_ATLAS_MAP.items():
            assert " — " in mapping, f"Missing separator in MITRE mapping for {check}"
            parts = mapping.split(" — ")
            assert len(parts) == 2
            assert parts[0].startswith("AML.T"), f"Invalid MITRE ID for {check}: {parts[0]}"


class TestRedactPaths:
    def test_redact_home_directory(self):
        finding = Finding(
            severity=Severity.INFO,
            category=FindingCategory.SUPPLY_CHAIN,
            check="test",
            detail="Found in /Users/carlosrocha/models/test",
            evidence={"file": "/Users/carlosrocha/models/test/config.json"},
        )
        redacted = redact_paths_in_finding(finding)
        assert "<redacted>" in redacted.detail
        assert "/Users/carlosrocha" not in redacted.detail
        assert "<redacted>" in str(redacted.evidence)
        assert "carlosrocha" not in str(redacted.evidence)

    def test_redact_tmp_directory(self):
        finding = Finding(
            severity=Severity.INFO,
            category=FindingCategory.LORA_BACKDOOR,
            check="test",
            detail="Found in /tmp/test123/adapter.safetensors",
            evidence={"path": "/tmp/test123/adapter.safetensors"},
        )
        redacted = redact_paths_in_finding(finding)
        assert "<redacted>" in redacted.detail
        assert "test123" not in redacted.detail

    def test_no_redact_when_not_matching(self):
        finding = Finding(
            severity=Severity.INFO,
            category=FindingCategory.SUPPLY_CHAIN,
            check="test",
            detail="Regular project path ./data/file.json",
            evidence={"file": "./data/file.json"},
        )
        redacted = redact_paths_in_finding(finding)
        assert "Regular project path ./data/file.json" in redacted.detail

    def test_empty_detail_and_evidence(self):
        finding = Finding(
            severity=Severity.INFO,
            category=FindingCategory.SUPPLY_CHAIN,
            check="test",
            detail="",
        )
        redacted = redact_paths_in_finding(finding)
        assert redacted.detail == ""
        assert redacted.evidence == {}


class TestScanDirectoryRedactPaths:
    def test_scan_with_redact(self, tmp_path: Path):
        result = scan_directory(tmp_path, redact_paths=True)
        assert result.target is not None  # Redact doesn't break output

    def test_scan_redact_preserves_findings(self, tmp_path: Path):
        result = scan_directory(tmp_path, redact_paths=True)
        assert hasattr(result, "findings")


class TestConfigurableDefaults:
    def test_default_max_file_size(self):
        assert DEFAULT_MAX_FILE_SIZE == 100 * 1024 * 1024

    def test_default_timeout(self):
        assert DEFAULT_TIMEOUT == 300

    def test_default_outlier_threshold(self):
        assert DEFAULT_OUTLIER_THRESHOLD == 3.0


class TestScanDirectoryConfigurable:
    def test_scan_with_custom_max_file_size(self, tmp_path: Path):
        result = scan_directory(tmp_path, max_file_size=1024)
        assert result is not None
        assert result.metadata.get("max_file_size") == 1024

    def test_scan_with_custom_timeout(self, tmp_path: Path):
        result = scan_directory(tmp_path, timeout=60)
        assert result is not None
        assert result.metadata.get("timeout") == 60

    def test_scan_with_custom_outlier_threshold(self, tmp_path: Path):
        result = scan_directory(tmp_path, outlier_threshold=2.5)
        assert result is not None
        assert result.metadata.get("outlier_threshold") == 2.5

    def test_scan_timeout_zero_disables(self, tmp_path: Path):
        result = scan_directory(tmp_path, timeout=0)
        assert result is not None

    def test_scan_timeout_triggers(self, tmp_path: Path):
        result = scan_directory(tmp_path, timeout=0.001)
        assert result is not None
        timeouts = [f for f in result.findings if f.check == "scan_timeout"]
        assert len(timeouts) > 0


class TestStreamLines:
    def test_stream_lines_small_file(self, tmp_path: Path):
        f = tmp_path / "test.jsonl"
        f.write_text("line1\nline2\nline3\n")
        lines = list(stream_lines(f))
        assert lines == ["line1\n", "line2\n", "line3\n"]

    def test_stream_lines_exceeds_max_size(self, tmp_path: Path):
        f = tmp_path / "large.jsonl"
        f.write_text("data\n")
        with pytest.raises(ValueError, match="exceeds max size"):
            list(stream_lines(f, max_size=1))


class TestUtf8ValidateFile:
    def test_valid_utf8(self, tmp_path: Path):
        f = tmp_path / "valid.txt"
        f.write_text("hello world", encoding="utf-8")
        valid, error = utf8_validate_file(f)
        assert valid is True
        assert error is None

    def test_invalid_utf8(self, tmp_path: Path):
        f = tmp_path / "invalid.txt"
        f.write_bytes(b"hello\xffworld")
        valid, error = utf8_validate_file(f)
        assert valid is False
        assert error is not None

    def test_missing_file(self, tmp_path: Path):
        f = tmp_path / "nonexistent.txt"
        valid, error = utf8_validate_file(f)
        assert valid is False
        assert error is not None


class TestReadTextSafe:
    def test_read_valid_utf8(self, tmp_path: Path):
        f = tmp_path / "valid.txt"
        f.write_text("hello world")
        content, warning = read_text_safe(f)
        assert content == "hello world"
        assert warning is None

    def test_read_invalid_utf8(self, tmp_path: Path):
        f = tmp_path / "invalid.txt"
        f.write_bytes(b"hello\xffworld")
        content, warning = read_text_safe(f)
        assert "hello" in content
        assert warning is not None
        assert "Invalid UTF-8" in warning

    def test_read_large_file(self, tmp_path: Path):
        f = tmp_path / "large.bin"
        f.write_bytes(b"x" * 200)
        content, warning = read_text_safe(f, max_size=100)
        assert content == ""
        assert warning is not None
        assert "exceeds max size" in warning
