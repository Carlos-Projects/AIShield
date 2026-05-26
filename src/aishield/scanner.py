"""Core scanning engine for AIShield.

Orchestrates dataset, LoRA, weight, and pipeline scans
into a unified finding model.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aishield.dataset.poisoning_detector import detect_poisoning
from aishield.dataset.provenance_verifier import verify_provenance
from aishield.dataset.statistics import analyze_dataset_stats
from aishield.lora.analyzer import analyze_lora
from aishield.lora.backdoor_detector import detect_lora_backdoors
from aishield.pipeline.auditor import audit_pipeline
from aishield.pipeline.supply_chain import analyze_supply_chain
from aishield.utils.crypto import sha256_string
from aishield.weights.fingerprinter import fingerprint_model
from aishield.weights.integrity_checker import check_weight_integrity

# MITRE ATLAS mappings for fine-tuning security findings
MITRE_ATLAS_MAP: dict[str, str] = {
    "poisoning_trigger_pattern": "AML.T0018 — Training Data Poisoning",
    "suspicious_instruction": "AML.T0018 — Training Data Poisoning",
    "label_flipping": "AML.T0018 — Training Data Poisoning",
    "duplicate_entries": "AML.T0018 — Training Data Poisoning",
    "role_imbalance": "AML.T0018 — Training Data Poisoning",
    "missing_provenance": "AML.T0017 — Supply Chain Compromise",
    "incomplete_provenance": "AML.T0017 — Supply Chain Compromise",
    "suspicious_target_modules": "AML.T0020 — ML Model Backdoor",
    "lora_embed_modification": "AML.T0020 — ML Model Backdoor",
    "lora_lm_head_modification": "AML.T0020 — ML Model Backdoor",
    "extreme_lora_weights": "AML.T0020 — ML Model Backdoor",
    "weight_integrity_failed": "AML.T0020 — ML Model Tampering",
    "fingerprint_mismatch": "AML.T0020 — ML Model Tampering",
    "no_weight_files": "AML.T0017 — Supply Chain Compromise",
    "unsafe_weight_format": "AML.T0025 — Adversarial Artifact",
    "missing_weight_manifest": "AML.T0017 — Supply Chain Compromise",
    "hardcoded_credential": "AML.T0024 — Credential Theft",
    "exposed_secret": "AML.T0024 — Credential Theft",
    "unsafe_model_load": "AML.T0025 — Adversarial Artifact",
    "suspicious_import": "AML.T0025 — Adversarial Artifact",
    "unknown_base_model": "AML.T0017 — Supply Chain Compromise",
    "missing_training_record": "AML.T0017 — Supply Chain Compromise",
    "missing_model_card": "AML.T0012 — Documentation Failure",
    "root_deployment": "AML.T0024 — Container Escape",
}

# Patterns to redact from paths when --redact-paths is used
REDACT_PATTERNS = [
    (r"/Users/[^/]+", "/Users/<redacted>"),
    (r"/home/[^/]+", "/home/<redacted>"),
    (r"/tmp/[^/]+", "/tmp/<redacted>"),
]


def redact_paths_in_finding(finding: Finding) -> Finding:
    """Redact sensitive path information from a finding's evidence."""
    if finding.evidence:
        redacted_evidence: dict[str, Any] = {}
        for k, v in finding.evidence.items():
            if isinstance(v, str):
                for pattern, replacement in REDACT_PATTERNS:
                    v = re.sub(pattern, replacement, v)
            redacted_evidence[k] = v
        finding.evidence = redacted_evidence
    if finding.detail:
        for pattern, replacement in REDACT_PATTERNS:
            finding.detail = re.sub(pattern, replacement, finding.detail)
    return finding


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Categories of fine-tuning security findings."""

    DATASET_POISONING = "dataset_poisoning"
    LORA_BACKDOOR = "lora_backdoor"
    WEIGHT_TAMPERING = "weight_tampering"
    PIPELINE_VULNERABILITY = "pipeline_vulnerability"
    SUPPLY_CHAIN = "supply_chain"
    PROVENANCE_FAILURE = "provenance_failure"
    CONFIGURATION_RISK = "configuration_risk"


class Finding(BaseModel):
    """A single security finding."""

    severity: Severity
    category: FindingCategory
    check: str
    detail: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str = ""
    mitre_atlas: str = ""


class ScanResult(BaseModel):
    """Complete scan result."""

    scan_id: str = ""
    timestamp: str = ""
    target: str = ""
    scan_type: str = "full"
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.scan_id:
            self.scan_id = sha256_string(f"{self.target}:{self.timestamp}")[:16]
        self.summary = self._compute_summary()

    def _compute_summary(self) -> dict[str, Any]:
        return {
            "total_findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
            "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            "categories": list(set(f.category.value for f in self.findings)),
        }

    @property
    def risk_score(self) -> int:
        """Compute risk score 0-100 based on findings."""
        score = 0
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        for f in self.findings:
            score += weights.get(f.severity, 0)
        return min(score, 100)


def scan_directory(
    path: Path,
    scan_types: list[str] | None = None,
    redact_paths: bool = False,
) -> ScanResult:
    """Scan a model directory for fine-tuning security issues.

    Args:
        path: Path to model or project directory.
        scan_types: List of scan types to run. None = all.
        redact_paths: If True, redact home directories from paths in output.

    Returns:
        ScanResult with all findings.
    """
    if scan_types is None:
        scan_types = ["dataset", "lora", "weights", "pipeline"]

    resolved = path.resolve()
    target = str(resolved)

    result = ScanResult(
        target=target,
        scan_type="full",
        metadata={"scan_types": scan_types, "python_version": "3.11+"},
    )

    if not resolved.exists():
        result.findings.append(
            Finding(
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION_RISK,
                check="path_not_found",
                detail=f"Path does not exist: {target}",
            )
        )
        result.summary = result._compute_summary()
        return result

    if "dataset" in scan_types:
        result.findings.extend(_scan_dataset(resolved))
    if "lora" in scan_types:
        result.findings.extend(_scan_lora(resolved))
    if "weights" in scan_types:
        result.findings.extend(_scan_weights(resolved))
    if "pipeline" in scan_types:
        result.findings.extend(_scan_pipeline(resolved))

    # Apply MITRE ATLAS mappings and optional path redaction
    for finding in result.findings:
        if finding.check in MITRE_ATLAS_MAP:
            finding.mitre_atlas = MITRE_ATLAS_MAP[finding.check]
        if redact_paths:
            redact_paths_in_finding(finding)

    if redact_paths:
        for pattern, replacement in REDACT_PATTERNS:
            result.target = re.sub(pattern, replacement, result.target)

    result.summary = result._compute_summary()
    return result


def _scan_dataset(path: Path) -> list[Finding]:
    """Run dataset poisoning checks."""
    findings: list[Finding] = []

    for pf in detect_poisoning(path):
        findings.append(
            Finding(
                severity=Severity(pf["severity"]),
                category=FindingCategory.DATASET_POISONING,
                check=pf["check"],
                detail=pf["detail"],
                evidence=pf.get("evidence", {}),
                recommendation=pf.get(
                    "recommendation", "Review dataset entries for malicious content"
                ),
            )
        )

    for pv in verify_provenance(path):
        findings.append(
            Finding(
                severity=Severity(pv["severity"]),
                category=FindingCategory.PROVENANCE_FAILURE,
                check=pv["check"],
                detail=pv["detail"],
                evidence=pv.get("evidence", {}),
                recommendation=pv.get(
                    "recommendation", "Verify dataset source and chain of custody"
                ),
            )
        )

    for ds in analyze_dataset_stats(path):
        findings.append(
            Finding(
                severity=Severity(ds["severity"]),
                category=FindingCategory.DATASET_POISONING,
                check=ds["check"],
                detail=ds["detail"],
                evidence=ds.get("evidence", {}),
                recommendation=ds.get("recommendation", ""),
            )
        )

    return findings


def _scan_lora(path: Path) -> list[Finding]:
    """Run LoRA adapter analysis checks."""
    findings: list[Finding] = []

    for la in analyze_lora(path):
        findings.append(
            Finding(
                severity=Severity(la["severity"]),
                category=FindingCategory.LORA_BACKDOOR,
                check=la["check"],
                detail=la["detail"],
                evidence=la.get("evidence", {}),
                recommendation=la.get(
                    "recommendation", "Inspect LoRA adapter for unauthorized modifications"
                ),
            )
        )

    for bd in detect_lora_backdoors(path):
        findings.append(
            Finding(
                severity=Severity(bd["severity"]),
                category=FindingCategory.LORA_BACKDOOR,
                check=bd["check"],
                detail=bd["detail"],
                evidence=bd.get("evidence", {}),
                recommendation=bd.get(
                    "recommendation",
                    "Remove suspicious LoRA adapter and retrain from trusted source",
                ),
            )
        )

    return findings


def _scan_weights(path: Path) -> list[Finding]:
    """Run model weight integrity checks."""
    findings: list[Finding] = []

    for wi in check_weight_integrity(path):
        findings.append(
            Finding(
                severity=Severity(wi["severity"]),
                category=FindingCategory.WEIGHT_TAMPERING,
                check=wi["check"],
                detail=wi["detail"],
                evidence=wi.get("evidence", {}),
                recommendation=wi.get(
                    "recommendation", "Verify model weights against trusted manifest"
                ),
            )
        )

    for fp in fingerprint_model(path):
        findings.append(
            Finding(
                severity=Severity(fp["severity"]),
                category=FindingCategory.WEIGHT_TAMPERING,
                check=fp["check"],
                detail=fp["detail"],
                evidence=fp.get("evidence", {}),
                recommendation=fp.get("recommendation", ""),
            )
        )

    return findings


def _scan_pipeline(path: Path) -> list[Finding]:
    """Run pipeline and supply chain checks."""
    findings: list[Finding] = []

    for ap in audit_pipeline(path):
        findings.append(
            Finding(
                severity=Severity(ap["severity"]),
                category=FindingCategory.PIPELINE_VULNERABILITY,
                check=ap["check"],
                detail=ap["detail"],
                evidence=ap.get("evidence", {}),
                recommendation=ap.get(
                    "recommendation", "Review fine-tuning pipeline configuration"
                ),
            )
        )

    for sc in analyze_supply_chain(path):
        findings.append(
            Finding(
                severity=Severity(sc["severity"]),
                category=FindingCategory.SUPPLY_CHAIN,
                check=sc["check"],
                detail=sc["detail"],
                evidence=sc.get("evidence", {}),
                recommendation=sc.get(
                    "recommendation", "Verify supply chain integrity from base model to deployment"
                ),
            )
        )

    return findings


def generate_report(result: ScanResult, fmt: str = "text") -> str:
    """Generate a human-readable report from scan results.

    Args:
        result: ScanResult to report on.
        fmt: Output format — "text", "json", or "html".

    Returns:
        Formatted report string.
    """
    if fmt == "json":
        return result.model_dump_json(indent=2)

    if fmt == "html":
        from aishield.reporters.html import render_html_report  # noqa: PLC0415

        return render_html_report(result)

    return _render_text_report(result)


def _render_text_report(result: ScanResult) -> str:
    """Render a text report with Rich-compatible markup."""
    lines = [
        "## AIShield Fine-Tuning Security Report",
        "",
        f"**Target:** {result.target}",
        f"**Scan ID:** {result.scan_id}",
        f"**Timestamp:** {result.timestamp}",
        f"**Risk Score:** {result.risk_score}/100",
        "",
        "### Summary",
        "",
        f"  Total findings: {result.summary['total_findings']}",
        f"  Critical: {result.summary['critical']}",
        f"  High: {result.summary['high']}",
        f"  Medium: {result.summary['medium']}",
        f"  Low: {result.summary['low']}",
        f"  Info: {result.summary['info']}",
        "",
    ]

    if not result.findings:
        lines.append("[green]No security findings detected.[/]")
        return "\n".join(lines)

    lines.append("### Findings")
    lines.append("")

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))

    for f in sorted_findings:
        icon = {
            Severity.CRITICAL: "[!!]",
            Severity.HIGH: "[!]",
            Severity.MEDIUM: "[?]",
            Severity.LOW: "[i]",
            Severity.INFO: "[~]",
        }.get(f.severity, "[?]")
        lines.append(f"  {icon} **{f.check}** ({f.severity.value}): {f.detail}")
        if f.recommendation:
            lines.append(f"      Recommendation: {f.recommendation}")
        lines.append("")

    return "\n".join(lines)
