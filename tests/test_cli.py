"""Tests for CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aishield.cli import app, main

runner = CliRunner()


class TestScanCommand:
    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "security scan" in result.output.lower()

    def test_scan_nonexistent(self):
        result = runner.invoke(app, ["scan", "/nonexistent/path/xyz123"])
        assert result.exit_code != 0

    def test_scan_empty_dir(self, tmp_path: Path):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        # Empty dirs have findings (e.g. no_weight_files), exit code may be 1
        assert result.exit_code in (0, 1)

    def test_scan_json_output(self, tmp_path: Path):
        result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
        assert result.exit_code in (0, 1)
        assert "target" in result.output


class TestDatasetCommand:
    def test_dataset_help(self):
        result = runner.invoke(app, ["dataset", "--help"])
        assert result.exit_code == 0

    def test_dataset_scan(self, tmp_path: Path):
        result = runner.invoke(app, ["dataset", str(tmp_path)])
        assert result.exit_code == 0


class TestLoraCommand:
    def test_lora_help(self):
        result = runner.invoke(app, ["lora", "--help"])
        assert result.exit_code == 0

    def test_lora_scan(self, tmp_path: Path):
        result = runner.invoke(app, ["lora", str(tmp_path)])
        assert result.exit_code == 0


class TestWeightsCommand:
    def test_weights_help(self):
        result = runner.invoke(app, ["weights", "--help"])
        assert result.exit_code == 0

    def test_weights_scan(self, tmp_path: Path):
        result = runner.invoke(app, ["weights", str(tmp_path)])
        assert result.exit_code == 0


class TestPipelineCommand:
    def test_pipeline_help(self):
        result = runner.invoke(app, ["pipeline", "--help"])
        assert result.exit_code == 0

    def test_pipeline_scan(self, tmp_path: Path):
        result = runner.invoke(app, ["pipeline", str(tmp_path)])
        assert result.exit_code == 0


class TestManifestCommand:
    def test_manifest_help(self):
        result = runner.invoke(app, ["manifest", "--help"])
        assert result.exit_code == 0

    def test_manifest_generate(self, tmp_path: Path):
        result = runner.invoke(app, ["manifest", str(tmp_path)])
        assert result.exit_code == 0
        assert "Manifest written" in result.output

    def test_manifest_verify_no_manifest(self, tmp_path: Path):
        result = runner.invoke(app, ["manifest", str(tmp_path), "--verify"])
        assert result.exit_code != 0


class TestSupplyChainCommand:
    def test_supply_chain_help(self):
        result = runner.invoke(app, ["supply-chain", "--help"])
        assert result.exit_code == 0

    def test_supply_chain_scan(self, tmp_path: Path):
        result = runner.invoke(app, ["supply-chain", str(tmp_path)])
        assert result.exit_code == 0


class TestMain:
    def test_main_entry(self):
        assert callable(main)
