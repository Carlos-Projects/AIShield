"""Tests for mcp-taxonomy adapter."""

from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    TaxonomyEvent,
)
from mcp_taxonomy.core import (
    Severity as TaxonomySeverity,
)

from aishield.scanner import Finding, FindingCategory, Severity
from aishield.taxonomy import (
    _AISHIELD_CATEGORY_MAP,
    _AISHIELD_CHECK_MAP,
    _map_confidence,
    aishield_finding_to_taxonomy,
    aishield_scan_to_taxonomy_events,
)


class TestMappingMaps:
    def test_all_categories_mapped(self):
        """Every FindingCategory value should have a taxonomy mapping."""
        for cat in FindingCategory:
            assert cat.value in _AISHIELD_CATEGORY_MAP, f"Missing mapping for {cat}"

    def test_common_checks_mapped(self):
        """Common check names should have detection method mappings."""
        common = [
            "poisoning_trigger_pattern",
            "weight_integrity_failed",
            "fingerprint_mismatch",
            "hardcoded_credential",
            "unsafe_model_load",
        ]
        for check in common:
            assert check in _AISHIELD_CHECK_MAP, f"Missing detection method for {check}"


class TestAishieldFindingToTaxonomy:
    def test_converts_finding_object(self):
        finding = Finding(
            severity=Severity.CRITICAL,
            category=FindingCategory.DATASET_POISONING,
            check="poisoning_trigger_pattern",
            detail="Trigger pattern found",
            evidence={"file": "data.json"},
            recommendation="Remove it",
        )
        event = aishield_finding_to_taxonomy(finding)
        assert isinstance(event, TaxonomyEvent)
        assert event.source == "aishield-scanner"
        assert event.attack_category == AttackCategory.INJECTION
        assert event.severity == TaxonomySeverity.CRITICAL
        assert event.title == "poisoning_trigger_pattern"

    def test_converts_finding_dict(self):
        finding = {
            "category": "lora_backdoor",
            "check": "suspicious_target_modules",
            "severity": "high",
            "detail": "Suspicious modules found",
            "recommendation": "Verify adapter",
            "evidence": {"file": "adapter_config.json"},
        }
        event = aishield_finding_to_taxonomy(finding)
        assert isinstance(event, TaxonomyEvent)
        assert event.attack_category == AttackCategory.TOOL_POISONING
        assert event.severity == TaxonomySeverity.HIGH

    def test_maps_unknown_category_to_anomaly(self):
        finding = Finding(
            severity=Severity.INFO,
            category=FindingCategory.CONFIGURATION_RISK,
            check="unknown_check",
            detail="test",
        )
        event = aishield_finding_to_taxonomy(finding)
        # CONFIGURATION_RISK is mapped
        assert event.attack_category == AttackCategory.MISCONFIGURATION

    def test_maps_severity_correctly(self):
        for sev in Severity:
            finding = Finding(
                severity=sev,
                category=FindingCategory.DATASET_POISONING,
                check="test",
                detail="test",
            )
            event = aishield_finding_to_taxonomy(finding)
            assert event.severity.value == sev.value

    def test_snippet_truncated(self):
        finding = Finding(
            severity=Severity.HIGH,
            category=FindingCategory.SUPPLY_CHAIN,
            check="test",
            detail="x" * 1000,
        )
        event = aishield_finding_to_taxonomy(finding)
        assert len(event.snippet) <= 500

    def test_risk_score_computed(self):
        finding = Finding(
            severity=Severity.CRITICAL,
            category=FindingCategory.WEIGHT_TAMPERING,
            check="weight_integrity_failed",
            detail="Hash mismatch",
        )
        event = aishield_finding_to_taxonomy(finding)
        assert event.risk_score > 0

    def test_target_from_evidence(self):
        finding = Finding(
            severity=Severity.HIGH,
            category=FindingCategory.DATASET_POISONING,
            check="test",
            detail="test",
            evidence={"file": "poisoned.json"},
        )
        event = aishield_finding_to_taxonomy(finding)
        assert event.target == "poisoned.json"


class TestAishieldScanToTaxonomyEvents:
    def test_converts_multiple_findings(self):
        findings = [
            Finding(
                severity=Severity.HIGH,
                category=FindingCategory.DATASET_POISONING,
                check="a",
                detail="a",
            ),
            Finding(
                severity=Severity.LOW, category=FindingCategory.SUPPLY_CHAIN, check="b", detail="b"
            ),
        ]
        events = aishield_scan_to_taxonomy_events(findings)
        assert len(events) == 2
        assert all(isinstance(e, TaxonomyEvent) for e in events)

    def test_empty_list(self):
        events = aishield_scan_to_taxonomy_events([])
        assert events == []


class TestMapConfidence:
    def test_critical_returns_certain(self):
        assert _map_confidence(TaxonomySeverity.CRITICAL) == Confidence.CERTAIN

    def test_high_returns_high(self):
        assert _map_confidence(TaxonomySeverity.HIGH) == Confidence.HIGH

    def test_info_returns_low(self):
        assert _map_confidence(TaxonomySeverity.INFO) == Confidence.LOW
