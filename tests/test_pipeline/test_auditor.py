"""Tests for pipeline auditor."""

from __future__ import annotations

from pathlib import Path

from aishield.pipeline.auditor import audit_pipeline


class TestAuditPipeline:
    def test_clean_project(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Project")
        findings = audit_pipeline(tmp_path)
        assert isinstance(findings, list)

    def test_hardcoded_credential(self, tmp_path: Path):
        script = 'HF_TOKEN = "hf_abc123def456ghi789jkl012mno345"\nprint("hello")'
        (tmp_path / "train.py").write_text(script)
        findings = audit_pipeline(tmp_path)
        creds = [f for f in findings if f["check"] == "hardcoded_credential"]
        assert len(creds) > 0
        assert creds[0]["severity"] == "critical"

    def test_unsafe_model_load(self, tmp_path: Path):
        script = "model = torch.load('model.bin', pickle_module=pickle)\n"
        (tmp_path / "train.py").write_text(script)
        findings = audit_pipeline(tmp_path)
        unsafe = [f for f in findings if f["check"] == "unsafe_model_load"]
        assert len(unsafe) > 0

    def test_suspicious_import(self, tmp_path: Path):
        script = "import subprocess\nsubprocess.run(['rm', '-rf', '/'])\n"
        (tmp_path / "train.py").write_text(script)
        findings = audit_pipeline(tmp_path)
        suspicious = [f for f in findings if f["check"] == "suspicious_import"]
        assert len(suspicious) > 0

    def test_credential_in_config(self, tmp_path: Path):
        config = 'api_key = "secret_key_12345678"\nepochs = 3\n'
        (tmp_path / "config.yaml").write_text(config)
        findings = audit_pipeline(tmp_path)
        creds = [f for f in findings if f["check"] == "credential_in_config"]
        assert len(creds) > 0

    def test_exposed_secret_in_env(self, tmp_path: Path):
        env = "HF_TOKEN=hf_abc123def456ghi789jkl012mno345\nDEBUG=true\n"
        (tmp_path / ".env").write_text(env)
        findings = audit_pipeline(tmp_path)
        exposed = [f for f in findings if f["check"] == "exposed_secret"]
        assert len(exposed) > 0

    def test_unpinned_dependencies(self, tmp_path: Path):
        reqs = "torch\nnumpy\ntransformers\n"
        (tmp_path / "requirements.txt").write_text(reqs)
        findings = audit_pipeline(tmp_path)
        unpinned = [f for f in findings if f["check"] == "unpinned_dependencies"]
        assert len(unpinned) > 0

    def test_pinned_dependencies(self, tmp_path: Path):
        reqs = "torch==2.1.0\nnumpy==1.26.0\ntransformers==4.35.0\n"
        (tmp_path / "requirements.txt").write_text(reqs)
        findings = audit_pipeline(tmp_path)
        unpinned = [f for f in findings if f["check"] == "unpinned_dependencies"]
        assert len(unpinned) == 0
