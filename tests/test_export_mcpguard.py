"""Tests for MCPGuard policy generation."""

from __future__ import annotations

from pathlib import Path

import yaml

from aishield.export.mcpguard import (
    _compute_rate_limit,
    generate_mcpguard_policy,
    save_mcpguard_policy,
)
from aishield.scanner import Finding, FindingCategory, ScanResult, Severity


class TestGenerateMCPGuardPolicy:
    def test_generates_yaml(self):
        result = ScanResult(target="/test")
        policy = generate_mcpguard_policy(result)
        assert policy.startswith("# MCPGuard Policy")
        assert "allow:" in policy
        assert "deny:" in policy
        assert "block_on_injection: true" in policy

    def test_denies_dangerous_tools(self):
        result = ScanResult(
            target="/test",
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    category=FindingCategory.PIPELINE_VULNERABILITY,
                    check="suspicious_import",
                    detail="import subprocess found in train.py",
                ),
            ],
        )
        policy = generate_mcpguard_policy(result)
        assert "exec" in policy
        assert "shell" in policy

    def test_allows_safe_tools_by_default(self):
        result = ScanResult(target="/test")
        policy = generate_mcpguard_policy(result)
        assert "get_weather" in policy
        assert "search_web" in policy

    def test_rate_limit_reduces_with_high_risk(self):
        low_result = ScanResult(target="/test")
        low_rate = _compute_rate_limit(low_result)

        high_result = ScanResult(
            target="/test",
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    category=FindingCategory.DATASET_POISONING,
                    check="a",
                    detail="a",
                )
            ]
            * 5,
        )
        high_rate = _compute_rate_limit(high_result)
        assert high_rate <= low_rate

    def test_denies_lora_modules(self):
        result = ScanResult(
            target="/test",
            findings=[
                Finding(
                    severity=Severity.HIGH,
                    category=FindingCategory.LORA_BACKDOOR,
                    check="suspicious_target_modules",
                    detail="LoRA adapter targets suspicious modules: lm_head, embed_tokens",
                    evidence={"target_modules": ["lm_head", "embed_tokens"]},
                ),
            ],
        )
        policy = generate_mcpguard_policy(result)
        assert "lm_head" in policy or "embed" in policy

    def test_valid_yaml_syntax(self):
        result = ScanResult(target="/test")
        policy = generate_mcpguard_policy(result)
        # Check it's valid YAML
        parsed = yaml.safe_load(policy)
        assert isinstance(parsed, dict)
        assert "mode" in parsed
        assert parsed["mode"] == "http"
        assert "allow" in parsed
        assert "deny" in parsed
        assert "block_on_injection" in parsed

    def test_high_risk_rate_limit_decreases(self):
        result = ScanResult(
            target="/test",
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    category=FindingCategory.DATASET_POISONING,
                    check="a",
                    detail="a",
                )
            ]
            * 3,
        )
        policy = generate_mcpguard_policy(result, rate_limit=100)
        # risk_score >= 50 => rate_limit = max(20, 100//3=33) = 33
        assert "rate_limit: 33" in policy


class TestSaveMCPGuardPolicy:
    def test_saves_to_file(self, tmp_path: Path):
        result = ScanResult(target="/test")
        output = tmp_path / "mcpguard.yaml"
        path = save_mcpguard_policy(result, str(output))
        assert path.exists()
        content = path.read_text()
        assert "MCPGuard Policy" in content
