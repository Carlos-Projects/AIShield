"""Tests for LoRA diff analysis."""

from __future__ import annotations

from pathlib import Path

from aishield.lora.diff import _assess_lora_risk, diff_lora_adapter, generate_lora_diff_report


class TestAssessLoraRisk:
    def test_low_risk(self):
        layers = [{"key": "base_model.model.layers.0.self_attn.q_proj.lora_A", "shape": [8, 4096]}]
        assert _assess_lora_risk(layers) == "low"

    def test_high_risk_embed(self):
        layers = [{"key": "base_model.model.model.embed_tokens.lora_A", "shape": [8, 4096]}]
        assert _assess_lora_risk(layers) == "high"

    def test_high_risk_lm_head(self):
        layers = [{"key": "base_model.model.lm_head.lora_A", "shape": [8, 4096]}]
        assert _assess_lora_risk(layers) == "high"

    def test_medium_risk(self):
        layers = [{"key": "base_model.model.layers.0.mlp.gate_proj.lora_A", "shape": [8, 4096]}]
        assert _assess_lora_risk(layers) == "medium"

    def test_empty_layers(self):
        assert _assess_lora_risk([]) == "unknown"


class TestDiffLoraAdapter:
    def test_no_adapter(self, tmp_path: Path):
        result = diff_lora_adapter(tmp_path)
        assert result["adapter_path"] == str(tmp_path)
        assert result["adapter_layers"] == []
        assert result["risk_assessment"] == "unknown"


class TestGenerateLoraDiffReport:
    def test_report_format(self, tmp_path: Path):
        report = generate_lora_diff_report(tmp_path)
        assert "LoRA Adapter Diff Report" in report
        assert "Risk Assessment" in report
