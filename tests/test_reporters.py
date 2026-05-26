"""Tests for reporters."""

from __future__ import annotations

import json

from aishield.reporters.console import render_console_report
from aishield.reporters.html import render_html_report, save_html_report
from aishield.reporters.json import render_json_report, save_json_report
from aishield.scanner import Finding, FindingCategory, ScanResult, Severity


class TestJsonReport:
    def test_render_json(self):
        r = ScanResult(target="/test")
        output = render_json_report(r)
        data = json.loads(output)
        assert data["target"] == "/test"

    def test_render_json_with_findings(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.HIGH, category=FindingCategory.DATASET_POISONING, check="test", detail="detail"),
            ],
        )
        output = render_json_report(r)
        data = json.loads(output)
        assert len(data["findings"]) == 1

    def test_save_json_report(self, tmp_path):
        r = ScanResult(target="/test")
        output_path = str(tmp_path / "report.json")
        save_json_report(r, output_path)
        assert (tmp_path / "report.json").exists()


class TestHtmlReport:
    def test_render_html(self):
        r = ScanResult(target="/test")
        html = render_html_report(r)
        assert "<!DOCTYPE html>" in html
        assert "AIShield" in html

    def test_render_html_with_findings(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.CRITICAL, category=FindingCategory.DATASET_POISONING, check="test", detail="detail"),
            ],
        )
        html = render_html_report(r)
        assert "test" in html
        assert "critical" in html.lower()

    def test_save_html_report(self, tmp_path):
        r = ScanResult(target="/test")
        output_path = str(tmp_path / "report.html")
        save_html_report(r, output_path)
        assert (tmp_path / "report.html").exists()

    def test_html_risk_score_display(self):
        r = ScanResult(
            target="/test",
            findings=[Finding(severity=Severity.CRITICAL, category=FindingCategory.DATASET_POISONING, check="a", detail="a")] * 5,
        )
        html = render_html_report(r)
        assert str(r.risk_score) in html


class TestConsoleReport:
    def test_render_console(self):
        r = ScanResult(target="/test")
        output = render_console_report(r)
        assert "AIShield" in output

    def test_render_console_with_findings(self):
        r = ScanResult(
            target="/test",
            findings=[
                Finding(severity=Severity.HIGH, category=FindingCategory.LORA_BACKDOOR, check="test", detail="detail"),
            ],
        )
        output = render_console_report(r)
        assert "test" in output
