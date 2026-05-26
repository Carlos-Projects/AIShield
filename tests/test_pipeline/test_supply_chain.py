"""Tests for supply chain analysis."""

from __future__ import annotations

import json
from pathlib import Path

from aishield.pipeline.supply_chain import analyze_supply_chain, generate_supply_chain_report


class TestAnalyzeSupplyChain:
    def test_unknown_base_model(self, tmp_path: Path):
        findings = analyze_supply_chain(tmp_path)
        unknown = [f for f in findings if f["check"] == "unknown_base_model"]
        assert len(unknown) > 0
        assert unknown[0]["severity"] == "high"

    def test_known_base_model(self, tmp_path: Path):
        config = {"_name_or_path": "meta-llama/Llama-2-7b"}
        (tmp_path / "config.json").write_text(json.dumps(config))
        findings = analyze_supply_chain(tmp_path)
        unknown = [f for f in findings if f["check"] == "unknown_base_model"]
        assert len(unknown) == 0

    def test_missing_training_record(self, tmp_path: Path):
        findings = analyze_supply_chain(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_training_record"]
        assert len(missing) > 0

    def test_missing_model_card(self, tmp_path: Path):
        findings = analyze_supply_chain(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_model_card"]
        assert len(missing) > 0

    def test_model_card_present(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# Model\n\n## Training\n## Evaluation\n## Limitations\n## Bias\n"
        )
        findings = analyze_supply_chain(tmp_path)
        missing = [f for f in findings if f["check"] == "missing_model_card"]
        assert len(missing) == 0

    def test_incomplete_model_card(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Model\nJust a model.\n")
        findings = analyze_supply_chain(tmp_path)
        incomplete = [f for f in findings if f["check"] == "incomplete_model_card"]
        assert len(incomplete) > 0

    def test_adapter_base_model(self, tmp_path: Path):
        config = {"base_model_name_or_path": "meta-llama/Llama-2-7b"}
        (tmp_path / "adapter_config.json").write_text(json.dumps(config))
        findings = analyze_supply_chain(tmp_path)
        unknown = [f for f in findings if f["check"] == "unknown_base_model"]
        assert len(unknown) == 0

    def test_root_deployment(self, tmp_path: Path):
        docker = 'FROM python:3.11\nUSER root\nCMD ["python", "serve.py"]\n'
        (tmp_path / "Dockerfile").write_text(docker)
        findings = analyze_supply_chain(tmp_path)
        root = [f for f in findings if f["check"] == "root_deployment"]
        assert len(root) > 0

    def test_exposed_port(self, tmp_path: Path):
        docker = (
            'FROM python:3.11\nEXPOSE 8080\nCMD ["python", "-m", "uvicorn", "--host", "0.0.0.0"]\n'
        )
        (tmp_path / "Dockerfile").write_text(docker)
        findings = analyze_supply_chain(tmp_path)
        exposed = [f for f in findings if f["check"] == "exposed_port"]
        assert len(exposed) > 0


class TestGenerateSupplyChainReport:
    def test_report_structure(self, tmp_path: Path):
        report = generate_supply_chain_report(tmp_path)
        assert "model_path" in report
        assert "supply_chain_stages" in report
        assert "trust_score" in report
        assert "findings" in report

    def test_trust_score_decreases_with_findings(self, tmp_path: Path):
        report = generate_supply_chain_report(tmp_path)
        assert 0 <= report["trust_score"] <= 100
