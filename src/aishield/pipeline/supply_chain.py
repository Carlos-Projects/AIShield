"""Supply chain analysis for fine-tuned models.

Analyzes the model supply chain from base model through fine-tuning
to deployment, identifying trust gaps and provenance failures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def analyze_supply_chain(path: Path) -> list[dict[str, Any]]:
    """Analyze model supply chain for security gaps.

    Traces the model lineage from base model → fine-tune → deploy
    and identifies missing links, unverified sources, and trust gaps.

    Args:
        path: Path to model or project directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    _check_base_model_provenance(path, findings)
    _check_fine_tuning_record(path, findings)
    _check_deployment_config(path, findings)
    _check_model_card(path, findings)

    return findings


def _check_base_model_provenance(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check base model provenance information."""
    base_model_found = False

    # Check config.json for base model reference
    config_file = path / "config.json"
    if config_file.exists():
        try:
            config = json.loads(config_file.read_text())
            base_model = config.get("_name_or_path", config.get("base_model", ""))
            if base_model:
                base_model_found = True
        except (json.JSONDecodeError, OSError):
            pass

    # Check adapter config
    adapter_config = path / "adapter_config.json"
    if adapter_config.exists():
        try:
            config = json.loads(adapter_config.read_text())
            base_model = config.get("base_model_name_or_path", "")
            if base_model:
                base_model_found = True
        except (json.JSONDecodeError, OSError):
            pass

    if not base_model_found:
        findings.append(
            {
                "severity": "high",
                "check": "unknown_base_model",
                "detail": "Base model cannot be determined — supply chain origin is unknown",
                "evidence": {"path": str(path)},
                "recommendation": "Document the base model used for fine-tuning in config or model card",
            }
        )


def _check_fine_tuning_record(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for fine-tuning training records."""
    record_files = [
        "training_args.json",
        "train_config.json",
        "fine_tune_record.json",
        "trainer_state.json",
        "training_log.json",
    ]
    found = any((path / rf).exists() for rf in record_files)

    if not found:
        findings.append(
            {
                "severity": "medium",
                "check": "missing_training_record",
                "detail": "No fine-tuning training record found — training parameters cannot be audited",
                "evidence": {"searched": record_files},
                "recommendation": "Save training configuration and hyperparameters for audit trail",
            }
        )


def _check_deployment_config(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check deployment configuration for security issues."""
    deploy_files = (
        list(path.glob("**/deploy*.yaml"))
        + list(path.glob("**/deploy*.json"))
        + list(path.glob("**/Dockerfile"))
        + list(path.glob("**/docker-compose*.yml"))
    )

    for df in deploy_files:
        if not df.is_file():
            continue
        try:
            content = df.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Check for running as root
        if "user: root" in content or "USER root" in content:
            findings.append(
                {
                    "severity": "medium",
                    "check": "root_deployment",
                    "detail": f"Deployment config {df.name} runs as root",
                    "evidence": {"file": df.name},
                    "recommendation": "Run model serving containers as non-root user",
                }
            )

        # Check for exposed ports
        if "0.0.0.0" in content:
            findings.append(
                {
                    "severity": "low",
                    "check": "exposed_port",
                    "detail": f"Deployment config {df.name} binds to 0.0.0.0",
                    "evidence": {"file": df.name},
                    "recommendation": "Bind to 127.0.0.1 or use a reverse proxy for production deployments",
                }
            )


def _check_model_card(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for model card documentation."""
    card_files = ["README.md", "model_card.md", "MODEL_CARD.md"]
    found = any((path / cf).exists() for cf in card_files)

    if not found:
        findings.append(
            {
                "severity": "low",
                "check": "missing_model_card",
                "detail": "No model card found — model capabilities, limitations, and training data are undocumented",
                "evidence": {"searched": card_files},
                "recommendation": "Create a model card documenting training data, evaluation, limitations, and intended use",
            }
        )
        return

    # Check model card for required sections
    readme = path / "README.md"
    if readme.exists():
        try:
            content = readme.read_text().lower()
            required_sections = ["training", "evaluation", "limitations", "bias"]
            missing = [s for s in required_sections if s not in content]
            if missing:
                findings.append(
                    {
                        "severity": "low",
                        "check": "incomplete_model_card",
                        "detail": f"Model card missing recommended sections: {', '.join(missing)}",
                        "evidence": {"missing_sections": missing},
                        "recommendation": "Add missing sections to model card for complete documentation",
                    }
                )
        except OSError:
            pass


def generate_supply_chain_report(path: Path) -> dict[str, Any]:
    """Generate a supply chain analysis report.

    Args:
        path: Path to model directory.

    Returns:
        Report dict with chain stages and trust assessment.
    """
    from aishield.scanner import scan_directory  # noqa: PLC0415

    result = scan_directory(path, scan_types=["pipeline"])

    report: dict[str, Any] = {
        "model_path": str(path.resolve()),
        "supply_chain_stages": {
            "base_model": "unknown",
            "fine_tuning": "unverified",
            "deployment": "unverified",
        },
        "trust_score": 0,
        "findings": [],
    }

    for f in result.findings:
        report["findings"].append(
            {
                "severity": f.severity.value,
                "category": f.category.value,
                "check": f.check,
                "detail": f.detail,
            }
        )

    # Compute trust score
    trust = 100
    for f in result.findings:
        if f.severity.value == "critical":
            trust -= 30
        elif f.severity.value == "high":
            trust -= 20
        elif f.severity.value == "medium":
            trust -= 10
        elif f.severity.value == "low":
            trust -= 5

    report["trust_score"] = max(0, trust)
    return report
