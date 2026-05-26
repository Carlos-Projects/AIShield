"""Tests for path redaction and other scanner enhancements."""

from __future__ import annotations

from pathlib import Path

from aishield.scanner import (
    MITRE_ATLAS_MAP,
    Finding,
    FindingCategory,
    Severity,
    redact_paths_in_finding,
    scan_directory,
)


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
