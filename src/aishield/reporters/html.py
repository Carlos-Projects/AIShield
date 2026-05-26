"""HTML reporter using Jinja2.

Renders scan results as HTML reports with charts and styling.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from aishield import __version__
from aishield.scanner import ScanResult, Severity

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIShield Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
        .container { max-width: 900px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 30px; }
        h1 { color: #1a1a2e; border-bottom: 2px solid #16213e; padding-bottom: 10px; }
        h2 { color: #16213e; margin-top: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .risk-score { font-size: 48px; font-weight: bold; padding: 20px; border-radius: 8px; text-align: center; min-width: 120px; }
        .risk-low { background: #d4edda; color: #155724; }
        .risk-medium { background: #fff3cd; color: #856404; }
        .risk-high { background: #f8d7da; color: #721c24; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }
        .summary-item { padding: 15px; border-radius: 6px; text-align: center; }
        .summary-item.critical { background: #f8d7da; }
        .summary-item.high { background: #fff3cd; }
        .summary-item.medium { background: #e2e3f1; }
        .summary-item.low { background: #d1ecf1; }
        .summary-item.info { background: #e8e8e8; }
        .summary-item .count { font-size: 24px; font-weight: bold; }
        .summary-item .label { font-size: 12px; text-transform: uppercase; }
        .finding { border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; background: #fafafa; border-radius: 0 4px 4px 0; }
        .finding.critical { border-color: #dc3545; }
        .finding.high { border-color: #ffc107; }
        .finding.medium { border-color: #6f42c1; }
        .finding.low { border-color: #17a2b8; }
        .finding.info { border-color: #6c757d; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; }
        .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .severity-badge.critical { background: #dc3545; color: white; }
        .severity-badge.high { background: #ffc107; color: #333; }
        .severity-badge.medium { background: #6f42c1; color: white; }
        .severity-badge.low { background: #17a2b8; color: white; }
        .severity-badge.info { background: #6c757d; color: white; }
        .recommendation { color: #666; font-style: italic; margin-top: 8px; }
        .meta { color: #666; font-size: 14px; }
        .footer { margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AIShield Security Report</h1>
            <div class="risk-score {{ risk_class }}">{{ result.risk_score }}</div>
        </div>

        <div class="meta">
            <p><strong>Target:</strong> {{ result.target }}</p>
            <p><strong>Scan ID:</strong> {{ result.scan_id }}</p>
            <p><strong>Timestamp:</strong> {{ result.timestamp }}</p>
        </div>

        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-item critical"><div class="count">{{ result.summary.critical }}</div><div class="label">Critical</div></div>
            <div class="summary-item high"><div class="count">{{ result.summary.high }}</div><div class="label">High</div></div>
            <div class="summary-item medium"><div class="count">{{ result.summary.medium }}</div><div class="label">Medium</div></div>
            <div class="summary-item low"><div class="count">{{ result.summary.low }}</div><div class="label">Low</div></div>
            <div class="summary-item info"><div class="count">{{ result.summary.info }}</div><div class="label">Info</div></div>
        </div>

        {% if result.findings %}
        <h2>Findings ({{ result.findings | length }})</h2>
        {% for f in sorted_findings %}
        <div class="finding {{ f.severity.value }}">
            <div class="finding-header">
                <strong>{{ f.check }}</strong>
                <span class="severity-badge {{ f.severity.value }}">{{ f.severity.value }}</span>
            </div>
            <p>{{ f.detail }}</p>
            {% if f.recommendation %}
            <p class="recommendation">Recommendation: {{ f.recommendation }}</p>
            {% endif %}
        </div>
        {% endfor %}
        {% else %}
        <h2>Findings</h2>
        <p style="color: #28a745; font-weight: bold;">No security findings detected.</p>
        {% endif %}

        <div class="footer">
            <p>Generated by AIShield v{{ version }} | https://github.com/Carlos-Projects/AIShield</p>
        </div>
    </div>
</body>
</html>"""


def render_html_report(result: ScanResult) -> str:
    """Render scan result as HTML report.

    Args:
        result: ScanResult to render.

    Returns:
        HTML string.
    """
    risk_class = (
        "risk-high"
        if result.risk_score >= 70
        else "risk-medium"
        if result.risk_score >= 40
        else "risk-low"
    )

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))

    template = Template(HTML_TEMPLATE)
    return template.render(
        result=result,
        sorted_findings=sorted_findings,
        risk_class=risk_class,
        version=__version__,
    )


def save_html_report(result: ScanResult, output_path: str) -> None:
    """Save scan result as HTML file.

    Args:
        result: ScanResult to save.
        output_path: Path to output file.
    """
    Path(output_path).write_text(render_html_report(result))
