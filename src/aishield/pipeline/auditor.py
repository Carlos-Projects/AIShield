"""Fine-tuning pipeline auditor.

Audits the fine-tuning pipeline configuration for security
vulnerabilities including unsafe training scripts, exposed credentials,
and insecure model loading.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Patterns indicating potential pipeline vulnerabilities
CREDENTIAL_PATTERNS = [
    re.compile(r"(?:api[_-]?key|token|secret|password)\s*[=:]\s*['\"]\w{8,}['\"]", re.IGNORECASE),
    re.compile(r"HF_TOKEN\s*=\s*['\"]\w{8,}['\"]", re.IGNORECASE),
    re.compile(r"wandb[_-]?api[_-]?key\s*[=:]\s*['\"]\w{8,}['\"]", re.IGNORECASE),
]

UNSAFE_LOAD_PATTERNS = [
    r"torch\.load\s*\([^)]*(?:pickle|pickle_module|map_location)",
    r"torch\.load\s*\([^)]*\)\.module",
    r"pickle\.load\s*\(",
    r"joblib\.load\s*\(",
]

SUSPICIOUS_IMPORTS = [
    "import subprocess",
    "import os.system",
    "exec(",
    "eval(",
    "__import__(",
]


def audit_pipeline(path: Path) -> list[dict[str, Any]]:
    """Audit fine-tuning pipeline for security issues.

    Scans training scripts, config files, and environment files
    for credential exposure, unsafe loading, and suspicious imports.

    Args:
        path: Path to project directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    _check_training_scripts(path, findings)
    _check_pipeline_configs(path, findings)
    _check_env_files(path, findings)
    _check_requirements(path, findings)

    return findings


def _check_training_scripts(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check training scripts for security issues."""
    script_files = list(path.glob("**/*.py"))

    for sf in script_files:
        if not sf.is_file():
            continue
        try:
            content = sf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Check for unsafe load patterns
        for pattern in UNSAFE_LOAD_PATTERNS:
            if re.search(pattern, content):
                findings.append(
                    {
                        "severity": "high",
                        "check": "unsafe_model_load",
                        "detail": f"Unsafe model loading pattern in {sf.name}: {pattern}",
                        "evidence": {"file": sf.name, "pattern": pattern},
                        "recommendation": "Use safetensors for model loading instead of pickle-based torch.load",
                    }
                )

        # Check for suspicious imports
        for imp in SUSPICIOUS_IMPORTS:
            if imp in content:
                findings.append(
                    {
                        "severity": "medium",
                        "check": "suspicious_import",
                        "detail": f"Suspicious import/call in {sf.name}: {imp}",
                        "evidence": {"file": sf.name, "import": imp},
                        "recommendation": "Review suspicious imports — may indicate malicious training script",
                    }
                )

        # Check for credential patterns
        for cred_pattern in CREDENTIAL_PATTERNS:
            if cred_pattern.search(content):
                findings.append(
                    {
                        "severity": "critical",
                        "check": "hardcoded_credential",
                        "detail": f"Hardcoded credential pattern in {sf.name}",
                        "evidence": {"file": sf.name, "pattern": cred_pattern.pattern},
                        "recommendation": "Remove hardcoded credentials — use environment variables or secret management",
                    }
                )


def _check_pipeline_configs(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check pipeline configuration files."""
    config_files = (
        list(path.glob("**/*.yaml"))
        + list(path.glob("**/*.yml"))
        + list(path.glob("**/training_config.json"))
    )

    for cf in config_files:
        if not cf.is_file():
            continue
        try:
            content = cf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Check for credentials in configs
        for cred_pattern in CREDENTIAL_PATTERNS:
            if cred_pattern.search(content):
                findings.append(
                    {
                        "severity": "critical",
                        "check": "credential_in_config",
                        "detail": f"Credential found in config file {cf.name}",
                        "evidence": {"file": cf.name, "pattern": cred_pattern.pattern},
                        "recommendation": "Remove credentials from config files — use environment variables",
                    }
                )


def _check_env_files(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check .env files for exposed secrets."""
    env_files = list(path.glob(".env")) + list(path.glob(".env.*"))

    for ef in env_files:
        if not ef.is_file():
            continue
        try:
            content = ef.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Check for actual secret values (not placeholders)
        secret_keys = ["HF_TOKEN", "OPENAI_API_KEY", "WANDB_API_KEY", "AWS_SECRET", "GOOGLE_KEY"]
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("\"'")
            if key in secret_keys and value and len(value) > 8:
                findings.append(
                    {
                        "severity": "critical",
                        "check": "exposed_secret",
                        "detail": f"Secret exposed in {ef.name}: {key}",
                        "evidence": {"file": ef.name, "key": key},
                        "recommendation": "Remove secrets from .env files — use a secrets manager",
                    }
                )


def _check_requirements(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check requirements files for known vulnerable packages."""
    req_files = list(path.glob("requirements*.txt")) + list(path.glob("pyproject.toml"))

    for rf in req_files:
        if not rf.is_file():
            continue
        try:
            content = rf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Check for unpinned dependencies
        lines_list = [
            line.strip()
            for line in content.split("\n")
            if line.strip() and not line.startswith("#")
        ]
        unpinned = [
            line
            for line in lines_list
            if ">=" not in line and "==" not in line and "~=" not in line and line.isalpha()
        ]
        if unpinned:
            findings.append(
                {
                    "severity": "low",
                    "check": "unpinned_dependencies",
                    "detail": f"{len(unpinned)} unpinned dependencies in {rf.name}",
                    "evidence": {"file": rf.name, "unpinned": unpinned[:10]},
                    "recommendation": "Pin all dependencies to specific versions for reproducible builds",
                }
            )
