"""Compliance checking against AI security frameworks.

Checks fine-tuning practices against NIST AI RMF, OWASP LLM Top 10,
and other security frameworks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# NIST AI RMF 1.0 — Map functions to checks
NIST_AIRMF_CHECKS = {
    "GOVERN": [
        ("risk_management_policy", "Documented risk management policy for AI systems"),
        ("supply_chain_risk", "Supply chain risk assessment for model components"),
        ("incident_response", "Incident response plan for AI security events"),
    ],
    "MAP": [
        ("context_documentation", "Documentation of AI system context and intended use"),
        ("capability_assessment", "Assessment of AI system capabilities and limitations"),
        ("impact_assessment", "Impact assessment for potential harms"),
    ],
    "MEASURE": [
        ("evaluation_metrics", "Evaluation metrics for model safety and security"),
        ("testing_procedures", "Testing procedures for adversarial robustness"),
        ("monitoring_setup", "Monitoring setup for deployed model behavior"),
    ],
    "MANAGE": [
        ("risk_treatment", "Risk treatment plan for identified AI risks"),
        ("incident_tracking", "Incident tracking and response procedures"),
        ("continuous_monitoring", "Continuous monitoring of model behavior"),
    ],
}

# OWASP LLM Top 10 categories
OWASP_LLM_CATEGORIES = [
    "LLM01: Prompt Injection",
    "LLM02: Insecure Output Handling",
    "LLM03: Training Data Poisoning",
    "LLM04: Model Denial of Service",
    "LLM05: Supply Chain Vulnerabilities",
    "LLM06: Sensitive Information Disclosure",
    "LLM07: Insecure Plugin Design",
    "LLM08: Excessive Agency",
    "LLM09: Overreliance",
    "LLM10: Model Theft",
]


def check_compliance(path: Path, framework: str = "nist") -> dict[str, Any]:
    """Check compliance against a security framework.

    Args:
        path: Path to model or project directory.
        framework: Framework to check against ("nist" or "owasp").

    Returns:
        Compliance report dict.
    """
    if framework == "nist":
        return _check_nist_airmf(path)
    elif framework == "owasp":
        return _check_owasp_llm(path)
    else:
        return {"error": f"Unknown framework: {framework}"}


def _check_nist_airmf(path: Path) -> dict[str, Any]:
    """Check compliance with NIST AI RMF 1.0."""
    result: dict[str, Any] = {
        "framework": "NIST AI RMF 1.0",
        "functions": {},
        "overall_score": 0,
    }

    total_checks = 0
    passed_checks = 0

    for function, checks in NIST_AIRMF_CHECKS.items():
        function_results = []
        for check_id, description in checks:
            status = _verify_check(path, check_id)
            function_results.append(
                {
                    "check": check_id,
                    "description": description,
                    "status": status,
                }
            )
            total_checks += 1
            if status == "pass":
                passed_checks += 1

        result["functions"][function] = function_results

    result["overall_score"] = round(passed_checks / total_checks * 100) if total_checks > 0 else 0
    return result


def _check_owasp_llm(path: Path) -> dict[str, Any]:
    """Check coverage against OWASP LLM Top 10."""
    result: dict[str, Any] = {
        "framework": "OWASP LLM Top 10",
        "categories": [],
        "coverage_score": 0,
    }

    covered = 0
    for category in OWASP_LLM_CATEGORIES:
        status = _verify_owasp_category(path, category)
        result["categories"].append(
            {
                "category": category,
                "status": status,
            }
        )
        if status != "not_covered":
            covered += 1

    result["coverage_score"] = round(covered / len(OWASP_LLM_CATEGORIES) * 100)
    return result


def _verify_check(path: Path, check_id: str) -> str:
    """Verify a specific compliance check.

    Args:
        path: Project directory.
        check_id: Check identifier.

    Returns:
        "pass", "fail", or "partial".
    """
    check_files = {
        "risk_management_policy": ["SECURITY.md", "RISK_ASSESSMENT.md"],
        "supply_chain_risk": ["aishield_manifest.json", "supply_chain.json"],
        "incident_response": ["INCIDENT_RESPONSE.md", "SECURITY.md"],
        "context_documentation": ["README.md", "model_card.md"],
        "capability_assessment": ["README.md", "EVALUATION.md"],
        "impact_assessment": ["RISK_ASSESSMENT.md", "IMPACT_ASSESSMENT.md"],
        "evaluation_metrics": ["EVALUATION.md", "metrics.json"],
        "testing_procedures": ["tests/", "test_*.py"],
        "monitoring_setup": ["monitoring.yaml", "alerting.yaml"],
        "risk_treatment": ["RISK_ASSESSMENT.md", "MITIGATION_PLAN.md"],
        "incident_tracking": ["INCIDENT_LOG.md", "SECURITY.md"],
        "continuous_monitoring": ["monitoring.yaml", "health_check.py"],
        "weight_manifest": ["aishield_manifest.json", "weight_manifest.json"],
        "access_control": [".env", "Dockerfile"],
    }

    files = check_files.get(check_id, [])
    for f in files:
        if (path / f).exists() or list(path.glob(f)):
            return "pass"
    return "fail"


def _verify_owasp_category(path: Path, category: str) -> str:
    """Verify coverage for an OWASP LLM category.

    Args:
        path: Project directory.
        category: OWASP LLM category string.

    Returns:
        "covered", "partial", or "not_covered".
    """
    category_checks = {
        "LLM01: Prompt Injection": ["prompt_injection", "injection"],
        "LLM02: Insecure Output Handling": ["output_validation", "sandbox"],
        "LLM03: Training Data Poisoning": ["dataset_poisoning", "provenance"],
        "LLM04: Model Denial of Service": ["rate_limit", "resource_limit"],
        "LLM05: Supply Chain Vulnerabilities": ["supply_chain", "provenance"],
        "LLM06: Sensitive Information Disclosure": ["data_masking", "pii_detection"],
        "LLM07: Insecure Plugin Design": ["plugin_security", "tool_validation"],
        "LLM08: Excessive Agency": ["agency_limit", "permission_check"],
        "LLM09: Overreliance": ["human_review", "confidence_score"],
        "LLM10: Model Theft": ["weight_manifest", "access_control"],
    }

    checks = category_checks.get(category, [])
    for check in checks:
        if _verify_check(path, check) == "pass":
            return "covered"
    return "not_covered"
