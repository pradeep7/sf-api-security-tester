"""Generates HTML and JSON reports from test findings."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader
from loguru import logger

from .models import (
    ExecutiveSummary,
    Evidence,
    FindingResult,
    FindingVerdict,
    Severity,
    TestReport,
)


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ report.project_name }} - Security Assessment Report</title>
<style>
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #484f58;
    --accent-blue: #58a6ff;
    --accent-green: #3fb950;
    --accent-red: #f85149;
    --accent-yellow: #d29922;
    --accent-purple: #bc8cff;
    --accent-orange: #f0883e;
    --critical-bg: #3d0000;
    --critical-border: #f85149;
    --high-bg: #3d1f00;
    --high-border: #f0883e;
    --medium-bg: #3d2f00;
    --medium-border: #d29922;
    --low-bg: #003d1f;
    --low-border: #3fb950;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
}

.container { max-width: 1400px; margin: 0 auto; padding: 20px; }

header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    padding: 40px;
    border-radius: 12px;
    margin-bottom: 30px;
    border: 1px solid var(--border);
}

header h1 {
    font-size: 28px;
    margin-bottom: 10px;
    background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

header .meta { color: var(--text-secondary); font-size: 14px; }

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 30px;
}

.summary-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    text-align: center;
    transition: transform 0.2s;
}

.summary-card:hover { transform: translateY(-2px); }

.summary-card .number {
    font-size: 36px;
    font-weight: 700;
    display: block;
    margin-bottom: 5px;
}

.summary-card .label {
    color: var(--text-secondary);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.summary-card.total .number { color: var(--accent-blue); }
.summary-card.findings .number { color: var(--accent-red); }
.summary-card.not-findings .number { color: var(--accent-green); }
.summary-card.na .number { color: var(--text-muted); }
.summary-card.errors .number { color: var(--accent-yellow); }
.summary-card.critical .number { color: var(--critical-border); }
.summary-card.high .number { color: var(--high-border); }
.summary-card.medium .number { color: var(--medium-border); }
.summary-card.low .number { color: var(--low-border); }

.section-title {
    font-size: 22px;
    margin: 30px 0 15px;
    padding-bottom: 10px;
    border-bottom: 2px solid var(--accent-blue);
}

.finding-item {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 16px;
    overflow: hidden;
}

.finding-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 20px;
    cursor: pointer;
    transition: background 0.2s;
}

.finding-header:hover { background: var(--bg-tertiary); }

.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
}

.badge-finding { background: #f85149; color: white; }
.badge-not-finding { background: #3fb950; color: white; }
.badge-na { background: var(--text-muted); color: white; }
.badge-error { background: #d29922; color: white; }

.severity-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
}

.severity-critical { background: var(--critical-bg); border: 1px solid var(--critical-border); color: var(--critical-border); }
.severity-high { background: var(--high-bg); border: 1px solid var(--high-border); color: var(--high-border); }
.severity-medium { background: var(--medium-bg); border: 1px solid var(--medium-border); color: var(--medium-border); }
.severity-low { background: var(--low-bg); border: 1px solid var(--low-border); color: var(--low-border); }

.confidence-badge {
    font-size: 11px;
    color: var(--text-secondary);
    padding: 2px 8px;
    border: 1px solid var(--border);
    border-radius: 12px;
}

.finding-title { font-size: 15px; font-weight: 600; flex-grow: 1; }

.finding-meta {
    font-size: 12px;
    color: var(--text-secondary);
    padding: 0 20px 12px;
}

.finding-details {
    display: none;
    padding: 0 20px 20px;
    border-top: 1px solid var(--border);
}

.finding-details.open { display: block; }

.detail-section {
    margin-top: 16px;
}

.detail-section h4 {
    font-size: 13px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.reasoning-box {
    background: var(--bg-tertiary);
    border-left: 3px solid var(--accent-blue);
    padding: 12px 16px;
    border-radius: 0 6px 6px 0;
    font-size: 13px;
    line-height: 1.5;
}

pre.http-dump {
    background: #0d1117;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
    font-size: 12px;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 400px;
    overflow-y: auto;
    color: var(--text-secondary);
}

.screenshot-container {
    margin-top: 10px;
}

.screenshot-container img {
    max-width: 100%;
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
}

.screenshot-container img:hover { border-color: var(--accent-blue); }

.toggle-btn {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 18px;
    padding: 0 4px;
    transition: transform 0.3s;
}

.toggle-btn.open { transform: rotate(90deg); }

.endpoint-url {
    font-family: 'Cascadia Code', monospace;
    font-size: 12px;
    color: var(--accent-blue);
    word-break: break-all;
}

table.summary-table {
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
}

table.summary-table th, table.summary-table td {
    padding: 10px 14px;
    border: 1px solid var(--border);
    text-align: left;
    font-size: 13px;
}

table.summary-table th {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

table.summary-table tr:hover { background: var(--bg-tertiary); }

.owasp-tag {
    font-size: 11px;
    padding: 2px 8px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--accent-purple);
    font-family: monospace;
}

footer {
    margin-top: 40px;
    padding: 20px;
    text-align: center;
    color: var(--text-muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
}

@media (max-width: 768px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
    .finding-header { flex-wrap: wrap; }
}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>&#x1f6e1; {{ report.project_name }}</h1>
    <div class="meta">
        Security Assessment Report | Generated: {{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}
        {% if report.executive_summary.portals_tested %}
        | Portals: {{ report.executive_summary.portals_tested | join(', ') }}
        {% endif %}
        {% if report.executive_summary.scan_start %}
        | Scan: {{ report.executive_summary.scan_start.strftime('%H:%M') }} - {{ report.executive_summary.scan_end.strftime('%H:%M') if report.executive_summary.scan_end else 'ongoing' }}
        {% endif %}
    </div>
</header>

<!-- Executive Summary -->
<h2 class="section-title">Executive Summary</h2>
<div class="summary-grid">
    <div class="summary-card total">
        <span class="number">{{ summary.total_tests }}</span>
        <span class="label">Total Tests</span>
    </div>
    <div class="summary-card findings">
        <span class="number">{{ summary.findings_count }}</span>
        <span class="label">Findings</span>
    </div>
    <div class="summary-card not-findings">
        <span class="number">{{ summary.not_findings_count }}</span>
        <span class="label">Not Findings</span>
    </div>
    <div class="summary-card na">
        <span class="number">{{ summary.na_count }}</span>
        <span class="label">N/A</span>
    </div>
    <div class="summary-card errors">
        <span class="number">{{ summary.errors_count }}</span>
        <span class="label">Errors</span>
    </div>
    <div class="summary-card critical">
        <span class="number">{{ summary.critical_count }}</span>
        <span class="label">Critical</span>
    </div>
    <div class="summary-card high">
        <span class="number">{{ summary.high_count }}</span>
        <span class="label">High</span>
    </div>
    <div class="summary-card medium">
        <span class="number">{{ summary.medium_count }}</span>
        <span class="label">Medium</span>
    </div>
    <div class="summary-card low">
        <span class="number">{{ summary.low_count }}</span>
        <span class="label">Low</span>
    </div>
</div>

<!-- Findings Table -->
{% if findings_list %}
<h2 class="section-title">Findings Detail</h2>
<table class="summary-table">
    <thead>
        <tr>
            <th>Severity</th>
            <th>Verdict</th>
            <th>Test Name</th>
            <th>OWASP</th>
            <th>Endpoint</th>
            <th>Portal</th>
            <th>Confidence</th>
        </tr>
    </thead>
    <tbody>
    {% for f in findings_list %}
        <tr>
            <td><span class="severity-badge severity-{{ f.severity.value|lower }}">{{ f.severity.value }}</span></td>
            <td><span class="badge badge-{{ f.verdict.value|lower|replace(' ', '-') }}">{{ f.verdict.value }}</span></td>
            <td>{{ f.test_name }}</td>
            <td><span class="owasp-tag">{{ f.owasp_category }}</span></td>
            <td class="endpoint-url">{{ f.endpoint_method }} {{ f.endpoint_url[:80] }}{% if f.endpoint_url|length > 80 %}...{% endif %}</td>
            <td>{{ f.portal_name }}</td>
            <td><span class="confidence-badge">{{ f.confidence.value }}</span></td>
        </tr>
    {% endfor %}
    </tbody>
</table>
{% endif %}

<!-- Detailed Findings (Expandable) -->
<h2 class="section-title">Detailed Evidence</h2>

{% for f in findings_list %}
<div class="finding-item" id="finding-{{ loop.index }}">
    <div class="finding-header" onclick="toggleDetails({{ loop.index }})">
        <button class="toggle-btn" id="toggle-{{ loop.index }}">&#x25B6;</button>
        <span class="badge badge-{{ f.verdict.value|lower|replace(' ', '-') }}">{{ f.verdict.value }}</span>
        <span class="severity-badge severity-{{ f.severity.value|lower }}">{{ f.severity.value }}</span>
        <span class="owasp-tag">{{ f.owasp_category }}</span>
        <span class="finding-title">{{ f.test_name }}</span>
        <span class="confidence-badge">{{ f.confidence.value }}</span>
    </div>
    <div class="finding-meta">
        {{ f.portal_name }} | {{ f.endpoint_method }} {{ f.endpoint_url[:100] }}{% if f.endpoint_url|length > 100 %}...{% endif %}
    </div>
    <div class="finding-details" id="details-{{ loop.index }}">

        <div class="detail-section">
            <h4>Reasoning</h4>
            <div class="reasoning-box">{{ f.reasoning }}</div>
        </div>

        {% if f.evidence %}
        <div class="detail-section">
            <h4>HTTP Request</h4>
            <pre class="http-dump">{{ f.evidence.raw_request_text or 'No raw request captured' }}</pre>
        </div>

        <div class="detail-section">
            <h4>HTTP Response</h4>
            <pre class="http-dump">{{ f.evidence.raw_response_text or 'No raw response captured' }}</pre>
        </div>

        {% if f.evidence.screenshot_path %}
        <div class="detail-section">
            <h4>Live Proof Screenshot</h4>
            <div class="screenshot-container">
                <img src="{{ f.evidence.screenshot_path }}" alt="Screenshot for {{ f.test_name }}" loading="lazy" onclick="window.open(this.src, '_blank')">
            </div>
        </div>
        {% endif %}

        <div class="detail-section">
            <h4>Evidence Metadata</h4>
            <table class="summary-table">
                <tr><td>Evidence ID</td><td>{{ f.evidence.id }}</td></tr>
                <tr><td>Execution Time</td><td>{{ f.evidence.execution_time_ms }}ms</td></tr>
                <tr><td>Test Case ID</td><td>{{ f.evidence.test_case_id }}</td></tr>
                <tr><td>Endpoint ID</td><td>{{ f.evidence.endpoint_id }}</td></tr>
                <tr><td>Timestamp</td><td>{{ f.evidence.timestamp.strftime('%Y-%m-%d %H:%M:%S') if f.evidence.timestamp else 'N/A' }}</td></tr>
            </table>
        </div>
        {% endif %}

        {% if f.error_message %}
        <div class="detail-section">
            <h4>Error Details</h4>
            <div class="reasoning-box" style="border-left-color: var(--accent-yellow);">{{ f.error_message }}</div>
        </div>
        {% endif %}

    </div>
</div>
{% endfor %}

<footer>
    SF API Security Tester v1.0 | Report generated by automated security testing framework
</footer>

</div>

<script>
function toggleDetails(index) {
    const details = document.getElementById('details-' + index);
    const toggle = document.getElementById('toggle-' + index);
    if (details.classList.contains('open')) {
        details.classList.remove('open');
        toggle.classList.remove('open');
    } else {
        details.classList.add('open');
        toggle.classList.add('open');
    }
}
</script>
</body>
</html>"""


class ReportGenerator:
    """Generates HTML and JSON security assessment reports."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, report: TestReport) -> dict[str, str]:
        """Generate all report formats. Returns dict of format -> file path."""
        output_files = {}

        # Generate JSON report
        json_path = self._generate_json(report)
        output_files["json"] = str(json_path)

        # Generate HTML report
        html_path = self._generate_html(report)
        output_files["html"] = str(html_path)

        logger.info(f"Reports generated: {output_files}")
        return output_files

    def _generate_json(self, report: TestReport) -> Path:
        """Generate JSON report."""
        report_data = {
            "project_name": report.project_name,
            "generated_at": report.generated_at.isoformat(),
            "executive_summary": {
                "total_tests": report.executive_summary.total_tests,
                "total_endpoints": report.executive_summary.total_endpoints,
                "findings_count": report.executive_summary.findings_count,
                "not_findings_count": report.executive_summary.not_findings_count,
                "na_count": report.executive_summary.na_count,
                "errors_count": report.executive_summary.errors_count,
                "critical_count": report.executive_summary.critical_count,
                "high_count": report.executive_summary.high_count,
                "medium_count": report.executive_summary.medium_count,
                "low_count": report.executive_summary.low_count,
                "scan_start": report.executive_summary.scan_start.isoformat() if report.executive_summary.scan_start else None,
                "scan_end": report.executive_summary.scan_end.isoformat() if report.executive_summary.scan_end else None,
                "portals_tested": report.executive_summary.portals_tested,
            },
            "findings": [self._finding_to_dict(f) for f in report.findings],
            "all_results": [self._finding_to_dict(f) for f in report.all_results],
        }

        json_path = self.output_dir / "security_report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

        return json_path

    def _generate_html(self, report: TestReport) -> Path:
        """Generate HTML report using Jinja2."""
        env = Environment(loader=BaseLoader(), autoescape=True)
        template = env.from_string(HTML_TEMPLATE)

        # Prepare findings list sorted by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        all_findings = sorted(
            report.all_results,
            key=lambda f: (
                0 if f.verdict == FindingVerdict.FINDING else 1,
                severity_order.get(f.severity, 99),
            ),
        )

        html_content = template.render(
            report=report,
            summary=report.executive_summary,
            findings_list=all_findings,
        )

        html_path = self.output_dir / "security_report.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return html_path

    def _finding_to_dict(self, finding: FindingResult) -> dict:
        """Convert FindingResult to a JSON-serializable dict."""
        result = {
            "id": finding.id,
            "test_case_id": finding.test_case_id,
            "test_name": finding.test_name,
            "endpoint_id": finding.endpoint_id,
            "endpoint_url": finding.endpoint_url,
            "endpoint_method": finding.endpoint_method,
            "portal_name": finding.portal_name,
            "owasp_category": finding.owasp_category,
            "owasp_name": finding.owasp_name,
            "severity": finding.severity.value,
            "verdict": finding.verdict.value,
            "confidence": finding.confidence.value,
            "reasoning": finding.reasoning,
            "error_message": finding.error_message,
            "timestamp": finding.timestamp.isoformat() if finding.timestamp else None,
        }

        if finding.evidence:
            result["evidence"] = {
                "id": finding.evidence.id,
                "execution_time_ms": finding.evidence.execution_time_ms,
                "screenshot_path": finding.evidence.screenshot_path,
                "timestamp": finding.evidence.timestamp.isoformat() if finding.evidence.timestamp else None,
                "request": {
                    "method": finding.evidence.request.method,
                    "url": finding.evidence.request.url,
                    "headers": finding.evidence.request.headers,
                    "body": finding.evidence.request.body,
                },
                "response": {
                    "status_code": finding.evidence.response.status_code,
                    "status_text": finding.evidence.response.status_text,
                    "headers": finding.evidence.response.headers,
                    "body": finding.evidence.response.body,
                },
            }

        return result
