"""Tests for LoRA analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.lora.analyzer import analyze_lora


class TestAnalyzeLora:
    def test_no_adapter(self, tmp_path: Path):
        findings = analyze_lora(tmp_path)
        assert findings == []

    def test_suspicious_target_modules(self, tmp_path: Path):
        config = {
            "base_model_name_or_path": "meta-llama/Llama-2-7b",
            "target_modules": ["lm_head", "embed_tokens"],
            "r": 8,
            "lora_alpha": 16,
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_lora(tmp_path)
        suspicious = [f for f in findings if f["check"] == "suspicious_target_modules"]
        assert len(suspicious) > 0
        assert suspicious[0]["severity"] == "high"

    def test_safe_target_modules(self, tmp_path: Path):
        config = {
            "base_model_name_or_path": "meta-llama/Llama-2-7b",
            "target_modules": ["q_proj", "k_proj", "v_proj"],
            "r": 8,
            "lora_alpha": 16,
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_lora(tmp_path)
        suspicious = [f for f in findings if f["check"] == "suspicious_target_modules"]
        assert len(suspicious) == 0

    def test_missing_base_model(self, tmp_path: Path):
        config = {"target_modules": ["q_proj"], "r": 8}
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_lora(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_base_model"]
        assert len(missing) > 0

    def test_high_lora_rank(self, tmp_path: Path):
        config = {
            "base_model_name_or_path": "meta-llama/Llama-2-7b",
            "target_modules": ["q_proj"],
            "r": 512,
            "lora_alpha": 1024,
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_lora(tmp_path)
        high_rank = [f for f in findings if f["check"] == "high_lora_rank"]
        assert len(high_rank) > 0

    def test_high_lora_scale(self, tmp_path: Path):
        config = {
            "base_model_name_or_path": "meta-llama/Llama-2-7b",
            "target_modules": ["q_proj"],
            "r": 4,
            "lora_alpha": 32,
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_lora(tmp_path)
        high_scale = [f for f in findings if f["check"] == "high_lora_scale"]
        assert len(high_scale) > 0

    def test_corrupt_adapter_config(self, tmp_path: Path):
        (tmp_path / "adapter_config.json").write_text("not json {{{")
        findings = analyze_lora(tmp_path)
        corrupt = [f for f in findings if f["check"] == "corrupt_adapter_config"]
        assert len(corrupt) > 0

    def test_uncommon_target_modules(self, tmp_path: Path):
        config = {
            "base_model_name_or_path": "meta-llama/Llama-2-7b",
            "target_modules": ["q_proj", "weird_layer_xyz"],
            "r": 8,
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_lora(tmp_path)
        uncommon = [f for f in findings if f["check"] == "uncommon_target_modules"]
        assert len(uncommon) > 0

    def test_subdirectory_adapter(self, tmp_path: Path):
        subdir = tmp_path / "adapter"
        subdir.mkdir()
        config = {"base_model_name_or_path": "test", "target_modules": ["lm_head"], "r": 8}
        (subdir / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_lora(tmp_path)
        suspicious = [f for f in findings if f["check"] == "suspicious_target_modules"]
        assert len(suspicious) > 0
