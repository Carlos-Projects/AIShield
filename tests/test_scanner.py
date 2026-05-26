"""Tests for core scanner module."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.scanner import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
    generate_report,
    scan_directory,
)


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestFindingCategory:
    def test_category_values(self):
        assert FindingCategory.DATASET_POISONING.value == "dataset_poisoning"
        assert FindingCategory.LORA_BACKDOOR.value == "lora_backdoor"
        assert FindingCategory.WEIGHT_TAMPERING.value == "weight_tampering"
        assert FindingCategory.PIPELINE_VULNERABILITY.value == "pipeline_vulnerability"
        assert FindingCategory.SUPPLY_CHAIN.value == "supply_chain"


class TestFinding:
    def test_create_finding(self):
        f = Finding(
            severity=Severity.HIGH,
            category=FindingCategory.DATASET_POISONING,
            check="test_check",
            detail="test detail",
        )
        assert f.severity == Severity.HIGH
        assert f.category == FindingCategory.DATASET_POISONING
        assert f.check == "test_check"
        assert f.detail == "test detail"
        assert f.evidence == {}
        assert f.recommendation == ""

    def test_finding_with_evidence(self):
        f = Finding(
            severity=Severity.CRITICAL,
            category=FindingCategory.LORA_BACKDOOR,
            check="backdoor_detected",
            detail="Backdoor found",
            evidence={"key": "value"},
            recommendation="Remove it",
        )
        assert f.evidence == {"key": "value"}
        assert f.recommendation == "Remove it"


class TestScanResult:
    def test_create_scan_result(self):
        r = ScanResult(target="/test/path")
        assert r.target == "/test/path"
        assert r.scan_type == "full"
        assert r.findings == []
        assert r.scan_id != ""
        assert r.timestamp != ""

    def test_scan_result_summary(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.CRITICAL, category=FindingCategory.DATASET_POISONING, check="a", detail="a"),
                Finding(severity=Severity.HIGH, category=FindingCategory.LORA_BACKDOOR, check="b", detail="b"),
                Finding(severity=Severity.INFO, category=FindingCategory.SUPPLY_CHAIN, check="c", detail="c"),
            ],
        )
        assert r.summary["total_findings"] == 3
        assert r.summary["critical"] == 1
        assert r.summary["high"] == 1
        assert r.summary["info"] == 1

    def test_risk_score_all_critical(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.CRITICAL, category=FindingCategory.DATASET_POISONING, check="a", detail="a"),
                Finding(severity=Severity.CRITICAL, category=FindingCategory.LORA_BACKDOOR, check="b", detail="b"),
                Finding(severity=Severity.CRITICAL, category=FindingCategory.WEIGHT_TAMPERING, check="c", detail="c"),
                Finding(severity=Severity.CRITICAL, category=FindingCategory.PIPELINE_VULNERABILITY, check="d", detail="d"),
                Finding(severity=Severity.CRITICAL, category=FindingCategory.SUPPLY_CHAIN, check="e", detail="e"),
            ],
        )
        assert r.risk_score == 100

    def test_risk_score_no_findings(self):
        r = ScanResult(target="/test")
        assert r.risk_score == 0

    def test_risk_score_mixed(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.HIGH, category=FindingCategory.DATASET_POISONING, check="a", detail="a"),
                Finding(severity=Severity.LOW, category=FindingCategory.SUPPLY_CHAIN, check="b", detail="b"),
            ],
        )
        assert r.risk_score == 18  # 15 + 3


class TestScanDirectory:
    def test_scan_empty_directory(self, tmp_path: Path):
        result = scan_directory(tmp_path)
        assert isinstance(result, ScanResult)
        assert result.target == str(tmp_path.resolve())

    def test_scan_nonexistent_directory(self):
        result = scan_directory(Path("/nonexistent/path/xyz"))
        assert isinstance(result, ScanResult)

    def test_scan_with_specific_types(self, tmp_path: Path):
        result = scan_directory(tmp_path, scan_types=["dataset"])
        assert isinstance(result, ScanResult)
        assert "dataset" in result.metadata.get("scan_types", [])


class TestGenerateReport:
    def test_text_report(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.HIGH, category=FindingCategory.DATASET_POISONING, check="test", detail="detail"),
            ],
        )
        report = generate_report(r, fmt="text")
        assert "AIShield" in report
        assert "test" in report

    def test_json_report(self):
        r = ScanResult(target="/test")
        report = generate_report(r, fmt="json")
        data = json.loads(report)
        assert data["target"] == "/test"

    def test_text_report_no_findings(self):
        r = ScanResult(target="/test")
        report = generate_report(r, fmt="text")
        assert "No security findings" in report

    def test_text_report_with_findings_sorted(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.INFO, category=FindingCategory.SUPPLY_CHAIN, check="info", detail="info"),
                Finding(severity=Severity.CRITICAL, category=FindingCategory.DATASET_POISONING, check="crit", detail="crit"),
            ],
        )
        report = generate_report(r, fmt="text")
        crit_pos = report.index("crit")
        info_pos = report.index("info")
        assert crit_pos < info_pos
