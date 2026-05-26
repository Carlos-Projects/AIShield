"""Tests for LoRA backdoor detector."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.lora.backdoor_detector import detect_lora_backdoors


class TestDetectLoraBackdoors:
    def test_no_adapter_files(self, tmp_path: Path):
        findings = detect_lora_backdoors(tmp_path)
        assert findings == []

    def test_trigger_keywords_in_config(self, tmp_path: Path):
        config = {
            "base_model_name_or_path": "test",
            "target_modules": ["q_proj"],
            "r": 8,
            "notes": "This adapter uses a trigger word to activate special behavior",
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = detect_lora_backdoors(tmp_path)
        trigger = [f for f in findings if f["check"] == "trigger_keywords_in_config"]
        assert len(trigger) > 0

    def test_clean_config(self, tmp_path: Path):
        config = {
            "base_model_name_or_path": "meta-llama/Llama-2-7b",
            "target_modules": ["q_proj", "v_proj"],
            "r": 8,
            "lora_alpha": 16,
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = detect_lora_backdoors(tmp_path)
        trigger = [f for f in findings if f["check"] == "trigger_keywords_in_config"]
        assert len(trigger) == 0

    def test_multiple_trigger_keywords(self, tmp_path: Path):
        config = {
            "description": "bypass safety and disable all filters for override mode",
            "target_modules": ["q_proj"],
        }
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = detect_lora_backdoors(tmp_path)
        trigger = [f for f in findings if f["check"] == "trigger_keywords_in_config"]
        assert len(trigger) > 0

    def test_unreadable_config(self, tmp_path: Path):
        (tmp_path / "adapter_config.json").write_text("not json {{{")
        findings = detect_lora_backdoors(tmp_path)
        assert isinstance(findings, list)
