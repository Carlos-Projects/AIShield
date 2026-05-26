"""Tests for compliance checking."""

from __future__ import annotations

from pathlib import Path

from aishield.pipeline.compliance import check_compliance


class TestCheckCompliance:
    def test_nist_framework(self, tmp_path: Path):
        result = check_compliance(tmp_path, framework="nist")
        assert result["framework"] == "NIST AI RMF 1.0"
        assert "functions" in result
        assert "GOVERN" in result["functions"]
        assert "MAP" in result["functions"]
        assert "MEASURE" in result["functions"]
        assert "MANAGE" in result["functions"]

    def test_owasp_framework(self, tmp_path: Path):
        result = check_compliance(tmp_path, framework="owasp")
        assert result["framework"] == "OWASP LLM Top 10"
        assert len(result["categories"]) == 10

    def test_unknown_framework(self, tmp_path: Path):
        result = check_compliance(tmp_path, framework="unknown")
        assert "error" in result

    def test_nist_score_range(self, tmp_path: Path):
        result = check_compliance(tmp_path, framework="nist")
        assert 0 <= result["overall_score"] <= 100

    def test_owasp_score_range(self, tmp_path: Path):
        result = check_compliance(tmp_path, framework="owasp")
        assert 0 <= result["coverage_score"] <= 100

    def test_nist_with_security_md(self, tmp_path: Path):
        (tmp_path / "SECURITY.md").write_text("# Security Policy")
        result = check_compliance(tmp_path, framework="nist")
        assert result["overall_score"] > 0

    def test_owasp_with_manifest(self, tmp_path: Path):
        (tmp_path / "aishield_manifest.json").write_text("{}")
        result = check_compliance(tmp_path, framework="owasp")
        assert result["coverage_score"] > 0
