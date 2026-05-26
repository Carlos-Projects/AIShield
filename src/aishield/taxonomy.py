"""AIShield finding adapter to mcp-taxonomy TaxonomyEvent.

Follows the same pattern as palisade_finding_to_taxonomy,
mcpguard_event_to_taxonomy, mcpwn_finding_to_taxonomy, and
agentgate_signal_to_taxonomy.
"""

from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    TaxonomyEvent,
    severity_weight,
)
from mcp_taxonomy.core import (
    Severity as TaxonomySeverity,
)

from aishield.scanner import Finding

_AISHIELD_CATEGORY_MAP: dict[str, AttackCategory] = {
    "dataset_poisoning": AttackCategory.INJECTION,
    "lora_backdoor": AttackCategory.TOOL_POISONING,
    "weight_tampering": AttackCategory.ANOMALY,
    "pipeline_vulnerability": AttackCategory.MISCONFIGURATION,
    "supply_chain": AttackCategory.POLICY_VIOLATION,
    "provenance_failure": AttackCategory.MISCONFIGURATION,
    "configuration_risk": AttackCategory.MISCONFIGURATION,
}

_AISHIELD_CHECK_MAP: dict[str, DetectionMethod] = {
    "poisoning_trigger_pattern": DetectionMethod.INJECTION_PATTERNS,
    "suspicious_instruction": DetectionMethod.PROMPT_INJECTION,
    "label_flipping": DetectionMethod.INJECTION_PATTERNS,
    "duplicate_entries": DetectionMethod.ENTROPY_ANALYZER,
    "role_imbalance": DetectionMethod.ENTROPY_ANALYZER,
    "missing_provenance": DetectionMethod.METADATA_ANALYZER,
    "suspicious_target_modules": DetectionMethod.TOOL_POISONING,
    "lora_embed_modification": DetectionMethod.TOOL_POISONING,
    "weight_integrity_failed": DetectionMethod.ANOMALY_DETECTOR,
    "fingerprint_mismatch": DetectionMethod.ANOMALY_DETECTOR,
    "hardcoded_credential": DetectionMethod.SURVEY,
    "exposed_secret": DetectionMethod.SURVEY,
    "unsafe_model_load": DetectionMethod.INJECTION_PATTERNS,
    "unknown_base_model": DetectionMethod.METADATA_ANALYZER,
    "missing_weight_manifest": DetectionMethod.SURVEY,
}


def aishield_finding_to_taxonomy(finding: Finding | dict) -> TaxonomyEvent:
    """Convert an AIShield Finding to a canonical TaxonomyEvent.

    Args:
        finding: AIShield Finding object or dict.

    Returns:
        TaxonomyEvent consumable by MCPscop.
    """

    def _extract_str_value(raw: str | dict) -> str:
        if isinstance(raw, str):
            return raw
        if isinstance(raw, dict):
            return raw.get("value", "")
        return ""

    if isinstance(finding, dict):
        cat_raw = finding.get("category", "")
        category_value = _extract_str_value(cat_raw)
        check = finding.get("check", "")
        sev_raw = finding.get("severity", "info")
        sev_str = _extract_str_value(sev_raw)
        detail = finding.get("detail", "")
        recommendation = finding.get("recommendation", "")
        evidence = finding.get("evidence", {})
        raw = finding
    else:
        category_value = (
            finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        )
        check = finding.check
        sev_str = (
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        )
        detail = finding.detail
        recommendation = finding.recommendation
        evidence = finding.evidence
        raw = None

    attack_category = _AISHIELD_CATEGORY_MAP.get(category_value, AttackCategory.ANOMALY)
    detection_method = _AISHIELD_CHECK_MAP.get(check, DetectionMethod.ANOMALY_DETECTOR)

    try:
        severity = TaxonomySeverity(sev_str)
    except ValueError:
        severity = TaxonomySeverity.MEDIUM

    confidence = _map_confidence(severity)

    risk_score = severity_weight(severity) * int(confidence.score * 100) // 25

    return TaxonomyEvent(
        source="aishield-scanner",
        attack_category=attack_category,
        severity=severity,
        confidence=confidence,
        detection_method=detection_method,
        title=check,
        description=detail,
        recommendation=recommendation,
        snippet=detail[:500],
        target=evidence.get("file", evidence.get("path", "")),
        raw=raw,
        risk_score=risk_score,
    )


def aishield_scan_to_taxonomy_events(
    findings: list[Finding] | list[dict],
) -> list[TaxonomyEvent]:
    """Convert multiple AIShield findings to TaxonomyEvents.

    Args:
        findings: List of AIShield Finding objects or dicts.

    Returns:
        List of TaxonomyEvent.
    """
    return [aishield_finding_to_taxonomy(f) for f in findings]


def _map_confidence(severity: TaxonomySeverity) -> Confidence:
    """Map severity level to a confidence score."""
    mapping = {
        TaxonomySeverity.CRITICAL: Confidence.CERTAIN,
        TaxonomySeverity.HIGH: Confidence.HIGH,
        TaxonomySeverity.MEDIUM: Confidence.MEDIUM,
        TaxonomySeverity.LOW: Confidence.LOW,
        TaxonomySeverity.INFO: Confidence.LOW,
    }
    return mapping.get(severity, Confidence.MEDIUM)
