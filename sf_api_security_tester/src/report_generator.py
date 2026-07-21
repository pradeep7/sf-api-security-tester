"""Generates HTML and JSON reports from test findings."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader
from loguru import logger

from .models import (
    ExecutiveSummary,
    Evidence,
    FeatureInventory,
    FindingResult,
    FindingVerdict,
    Severity,
    SiteMap,
    TestReport,
)


# ---------------------------------------------------------------------------
# OWASP standards metadata: display name + ordered category list
# ---------------------------------------------------------------------------
_OWASP_STANDARDS: dict[str, dict[str, Any]] = {
    "owasp_api_2023": {
        "full_name": "OWASP API Security Top 10 (2023)",
        "short_name": "API Top 10",
        "categories": [
            ("API1", "Broken Object Level Authorization"),
            ("API2", "Broken Authentication"),
            ("API3", "Broken Function Level Authorization"),
            ("API4", "Unrestricted Resource Consumption"),
            ("API5", "Broken Function Level Authorization"),
            ("API6", "Unrestricted Access to Sensitive Business Flows"),
            ("API7", "Server Side Request Forgery"),
            ("API8", "Security Misconfiguration"),
            ("API9", "Improper Inventory Management"),
            ("API10", "Unsafe Consumption of APIs"),
        ],
    },
    "owasp_web_2021": {
        "full_name": "OWASP Web Application Top 10 (2021)",
        "short_name": "Web Top 10",
        "categories": [
            ("A01", "Broken Access Control"),
            ("A02", "Cryptographic Failures"),
            ("A03", "Injection"),
            ("A04", "Insecure Design"),
            ("A05", "Security Misconfiguration"),
            ("A06", "Vulnerable and Outdated Components"),
            ("A07", "Identification and Authentication Failures"),
            ("A08", "Software and Data Integrity Failures"),
            ("A09", "Security Logging and Monitoring Failures"),
            ("A10", "Server-Side Request Forgery"),
        ],
    },
    "owasp_scp_v2": {
        "full_name": "OWASP Secure Coding Practices Quick Reference Guide (v2)",
        "short_name": "Secure Coding",
        "categories": [
            ("SCP-01", "Input Validation"),
            ("SCP-02", "Output Encoding"),
            ("SCP-03", "Authentication"),
            ("SCP-04", "Session Management"),
            ("SCP-05", "Access Control"),
            ("SCP-06", "Cryptographic Practices"),
            ("SCP-07", "Error Handling and Logging"),
            ("SCP-08", "Data Protection and Privacy"),
            ("SCP-09", "Communications Security"),
            ("SCP-10", "System Configuration"),
            ("SCP-11", "Database Security"),
            ("SCP-12", "File Management"),
            ("SCP-13", "Memory Management"),
        ],
    },
}


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

/* --- Residual Risk Disclaimer (V4.0) --- */
.residual-risk-disclaimer {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 16px 20px;
    background: rgba(210, 153, 34, 0.1);
    border: 1px solid var(--accent-yellow);
    border-radius: 8px;
    margin-bottom: 24px;
}

.disclaimer-icon {
    font-size: 24px;
    flex-shrink: 0;
}

.disclaimer-content {
    font-size: 13px;
    color: var(--text-primary);
    line-height: 1.5;
}

.disclaimer-content strong {
    color: var(--accent-yellow);
}

/* --- Evidence Checklist (V4.0) --- */
.evidence-checklist {
    margin-top: 8px;
    padding: 8px 12px;
    background: var(--bg-tertiary);
    border-radius: 6px;
    font-size: 12px;
}

.evidence-item {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 2px 0;
}

.evidence-captured { color: var(--accent-green); }
.evidence-missing { color: var(--accent-red); }

/* --- Workflow Visualization (V3.1) --- */
.workflows-section { margin-bottom: 30px; }

.workflow-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 16px;
}

.workflow-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
}

.workflow-badge {
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 12px;
    background: rgba(188,140,255,0.15);
    color: var(--accent-purple);
    border: 1px solid rgba(188,140,255,0.3);
    font-family: monospace;
    text-transform: uppercase;
}

.workflow-name {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
}

.workflow-flowchart {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 16px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow-x: auto;
    flex-wrap: nowrap;
}

.workflow-step {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    min-width: 140px;
    text-align: center;
    flex-shrink: 0;
}

.step-number {
    display: inline-block;
    width: 24px;
    height: 24px;
    line-height: 24px;
    border-radius: 50%;
    background: var(--accent-blue);
    color: white;
    font-size: 12px;
    font-weight: 700;
    margin-bottom: 6px;
}

.step-action {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 4px;
}

.step-url {
    font-size: 10px;
    color: var(--text-muted);
    font-family: monospace;
    word-break: break-all;
}

.step-params {
    font-size: 9px;
    color: var(--accent-yellow);
    margin-top: 4px;
}

.workflow-arrow {
    font-size: 20px;
    color: var(--accent-blue);
    flex-shrink: 0;
}

.workflow-results {
    margin-top: 16px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
}

.workflow-results h4 {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 8px;
}

.workflow-test-result {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
}

.workflow-test-id {
    font-size: 12px;
    color: var(--text-primary);
    font-family: monospace;
}

.workflow-result-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
}

.workflow-result-pass { background: rgba(63,185,80,0.2); color: var(--accent-green); }
.workflow-result-fail { background: rgba(248,81,73,0.2); color: var(--accent-red); }
.workflow-result-na { background: var(--bg-tertiary); color: var(--text-muted); }

.workflow-empty {
    text-align: center;
    padding: 30px;
    color: var(--text-muted);
    font-size: 14px;
    background: var(--bg-secondary);
    border: 1px dashed var(--border);
    border-radius: 8px;
}

/* --- Feature Inventory (V3.0) --- */
.inventory-section { margin-bottom: 30px; }

.inventory-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}

.inventory-stat {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    text-align: center;
}

.inventory-stat .num {
    font-size: 28px;
    font-weight: 700;
    color: var(--accent-blue);
    display: block;
}

.inventory-stat .lbl {
    color: var(--text-secondary);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.inventory-table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
}

.inventory-table th,
.inventory-table td {
    padding: 8px 12px;
    border: 1px solid var(--border);
    font-size: 12px;
    text-align: left;
}

.inventory-table th {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 10px;
}

.inventory-table tr:hover td { background: rgba(88,166,255,0.04); }

.inv-cat-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
}

.inv-cat-dashboard { background: rgba(88,166,255,0.15); color: var(--accent-blue); }
.inv-cat-list_view { background: rgba(63,185,80,0.15); color: var(--accent-green); }
.inv-cat-record_detail { background: rgba(188,140,255,0.15); color: var(--accent-purple); }
.inv-cat-form { background: rgba(240,136,62,0.15); color: var(--accent-orange); }
.inv-cat-settings { background: rgba(210,153,34,0.15); color: var(--accent-yellow); }
.inv-cat-admin { background: rgba(248,81,73,0.15); color: var(--accent-red); }
.inv-cat-login { background: var(--bg-tertiary); color: var(--text-secondary); }
.inv-cat-other { background: var(--bg-tertiary); color: var(--text-muted); }

.risk-tag {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 9px;
    font-weight: 600;
    margin: 1px;
    text-transform: uppercase;
}

.risk-xss { background: rgba(248,81,73,0.2); color: var(--accent-red); }
.risk-sqli { background: rgba(248,81,73,0.3); color: var(--accent-red); }
.risk-ssrf { background: rgba(240,136,62,0.2); color: var(--accent-orange); }
.risk-none { background: var(--bg-tertiary); color: var(--text-muted); }

.sensitive-badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 9px;
    font-weight: 600;
    background: rgba(248,81,73,0.15);
    color: var(--accent-red);
}

/* --- Visual Evidence (V3.0) --- */
.visual-evidence {
    display: flex;
    gap: 16px;
    margin-top: 12px;
    padding: 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 8px;
}

.visual-evidence-img {
    flex-shrink: 0;
    max-width: 320px;
}

.visual-evidence-img img {
    max-width: 100%;
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
}

.visual-evidence-img img:hover { border-color: var(--accent-blue); }

.visual-evidence-text { flex: 1; min-width: 0; }

.visual-verdict-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    margin-bottom: 8px;
}

.vv-confirmed_xss { background: rgba(248,81,73,0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
.vv-reflected_not_executed { background: rgba(210,153,34,0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
.vv-data_exposure { background: rgba(240,136,62,0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }
.vv-inconclusive { background: var(--bg-secondary); color: var(--text-secondary); border: 1px solid var(--border); }
.vv-clean { background: rgba(63,185,80,0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }

.visual-evidence-label {
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 8px;
    margin-bottom: 4px;
}

.visual-evidence-content {
    font-size: 12px;
    color: var(--text-primary);
    line-height: 1.5;
}

@media (max-width: 768px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
    .finding-header { flex-wrap: wrap; }
}

/* --- OWASP Compliance Matrix --- */
.compliance-section { margin-bottom: 30px; }

.compliance-standard {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
}

.compliance-standard-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    background: var(--bg-tertiary);
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.2s;
}

.compliance-standard-header:hover { background: #282e38; }

.compliance-standard-header h3 {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
}

.compliance-standard-header .std-short {
    font-size: 11px;
    color: var(--accent-purple);
    padding: 2px 8px;
    background: rgba(188,140,255,0.1);
    border: 1px solid rgba(188,140,255,0.3);
    border-radius: 4px;
    font-family: monospace;
}

.compliance-table {
    width: 100%;
    border-collapse: collapse;
}

.compliance-table th,
.compliance-table td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    text-align: center;
    font-size: 13px;
}

.compliance-table th {
    background: var(--bg-primary);
    color: var(--text-secondary);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 11px;
    position: sticky;
    top: 0;
}

.compliance-table td:first-child,
.compliance-table th:first-child {
    text-align: left;
    min-width: 200px;
}

.compliance-table tr:last-child td { border-bottom: none; }
.compliance-table tr:hover td { background: rgba(88,166,255,0.04); }

.compliance-table .cat-code {
    font-family: monospace;
    font-weight: 600;
    color: var(--accent-blue);
    white-space: nowrap;
}

.compliance-table .cat-name {
    color: var(--text-primary);
}

/* Coverage bar */
.cov-cell { min-width: 110px; }

.cov-bar-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
}

.cov-bar {
    flex: 1;
    height: 8px;
    background: var(--bg-primary);
    border-radius: 4px;
    overflow: hidden;
    min-width: 50px;
}

.cov-bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.4s ease;
}

.cov-bar-fill.cov-100 { background: var(--accent-green); }
.cov-bar-fill.cov-high { background: var(--accent-blue); }
.cov-bar-fill.cov-med { background: var(--accent-yellow); }
.cov-bar-fill.cov-low { background: var(--accent-red); }
.cov-bar-fill.cov-zero { background: var(--text-muted); }

.cov-pct {
    font-size: 12px;
    font-weight: 600;
    min-width: 38px;
    text-align: right;
}

.cov-pct.pct-100 { color: var(--accent-green); }
.cov-pct.pct-high { color: var(--accent-blue); }
.cov-pct.pct-med { color: var(--accent-yellow); }
.cov-pct.pct-low { color: var(--accent-red); }
.cov-pct.pct-zero { color: var(--text-muted); }

/* Count badges in cells */
.cnt-badge {
    display: inline-block;
    min-width: 22px;
    padding: 1px 6px;
    border-radius: 10px;
    font-size: 12px;
    font-weight: 600;
}

.cnt-total { color: var(--text-secondary); }
.cnt-passed { color: var(--accent-green); }
.cnt-finding { color: var(--accent-red); background: rgba(248,81,73,0.1); }
.cnt-na { color: var(--text-muted); }
.cnt-error { color: var(--accent-yellow); }

/* Summary row */
.compliance-table tr.compliance-total td {
    background: var(--bg-tertiary);
    font-weight: 600;
    border-top: 2px solid var(--border);
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

<!-- Residual Risk Disclaimer (V4.0) -->
<div class="residual-risk-disclaimer">
    <div class="disclaimer-icon">&#x26A0;&#xFE0F;</div>
    <div class="disclaimer-content">
        <strong>Residual Risk Statement:</strong> This assessment is evidence-backed only for the
        executed route, role, method, data context, and environment. It does not prove alternate
        roles, routes, versions, batch paths, or trust boundaries. Untested variants, exclusions,
        and residual risk must be reviewed manually.
    </div>
</div>

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

<!-- Application Feature Inventory (V3.0) -->
{% if site_map and site_map.pages %}
<h2 class="section-title">Application Feature Inventory</h2>
<div class="inventory-section">
    <div class="inventory-grid">
        <div class="inventory-stat">
            <span class="num">{{ site_map.total_pages }}</span>
            <span class="lbl">Pages Discovered</span>
        </div>
        <div class="inventory-stat">
            <span class="num">{{ site_map.total_input_fields }}</span>
            <span class="lbl">Input Fields</span>
        </div>
        <div class="inventory-stat">
            <span class="num">{{ site_map.sensitive_pages | length }}</span>
            <span class="lbl">Sensitive Pages</span>
        </div>
        <div class="inventory-stat">
            <span class="num">{{ feature_inventory.total_risks if feature_inventory else 0 }}</span>
            <span class="lbl">Risk Surfaces</span>
        </div>
    </div>

    {% if feature_inventory and feature_inventory.risk_surfaces %}
    <h3 style="font-size:14px;color:var(--text-secondary);margin-bottom:8px;">Risk Surfaces</h3>
    <table class="inventory-table">
        <thead>
            <tr>
                <th>Risk Type</th>
                <th>Severity</th>
                <th>Affected Pages</th>
                <th>Input Fields</th>
                <th>Recommended Tests</th>
            </tr>
        </thead>
        <tbody>
        {% for risk in feature_inventory.risk_surfaces %}
            <tr>
                <td><span class="risk-tag risk-{{ risk.risk_type }}">{{ risk.risk_type | upper }}</span></td>
                <td><span class="severity-badge severity-{{ risk.severity.value|lower }}">{{ risk.severity.value }}</span></td>
                <td>{{ risk.pages | length }} page(s)</td>
                <td>{{ risk.input_fields | length }} field(s)</td>
                <td>{% for t in risk.recommended_tests %}<span class="owasp-tag" style="margin:1px;">{{ t }}</span>{% endfor %}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% endif %}

    {% if site_map.pages %}
    <h3 style="font-size:14px;color:var(--text-secondary);margin:16px 0 8px;">Discovered Pages (Tree View)</h3>
    <div style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:monospace;font-size:12px;max-height:600px;overflow-y:auto;">
    {# Build tree: group pages by parent_url #}
    {% set ns = namespace(tree={}, node_id=0) %}
    {% for page in site_map.pages %}
        {% set parent = page.parent_url or 'root' %}
        {% if parent not in ns.tree %}
            {% set _ = ns.tree.update({parent: []}) %}
        {% endif %}
        {% set _ = ns.tree[parent].append(page) %}
    {% endfor %}

    {# Render tree recursively with collapsible nodes #}
    {% macro render_node(parent_url, depth) %}
        {% if parent_url in ns.tree %}
            {% for page in ns.tree[parent_url] %}
                {% set ns.node_id = ns.node_id + 1 %}
                {% set has_children = page.url in ns.tree %}
                <div style="padding-left:{{ depth * 20 }}px;margin:2px 0;">
                    {% if has_children %}
                    <span class="tree-toggle" id="tree-btn-{{ ns.node_id }}" onclick="toggleTreeNode('{{ ns.node_id }}')" style="cursor:pointer;color:var(--accent-blue);font-size:10px;display:inline-block;width:14px;text-align:center;">&#x25BC;</span>
                    {% else %}
                    <span style="display:inline-block;width:14px;text-align:center;color:var(--text-muted);font-size:10px;">&#x25CF;</span>
                    {% endif %}
                    <span class="inv-cat-badge inv-cat-{{ page.page_category }}" style="font-size:9px;">{{ page.page_category }}</span>
                    <span style="color:var(--text-primary);">{{ page.title[:40] or page.url[:50] }}</span>
                    <span style="color:var(--text-muted);font-size:10px;">({{ page.input_fields | length }} inputs)</span>
                    {% if page.sensitive_data_visible %}<span class="sensitive-badge" style="font-size:8px;">SENSITIVE</span>{% endif %}
                </div>
                {% if has_children %}
                <div id="tree-children-{{ ns.node_id }}" style="padding-left:{{ depth * 20 + 14 }}px;border-left:1px dashed var(--border);margin-left:{{ depth * 20 + 6 }}px;">
                    {{ render_node(page.url, depth + 1) }}
                </div>
                {% endif %}
            {% endfor %}
        {% endif %}
    {% endmacro %}

    {{ render_node('root', 0) }}
    </div>

    <h3 style="font-size:14px;color:var(--text-secondary);margin:16px 0 8px;">Discovered Pages (Table View)</h3>
    <table class="inventory-table">
        <thead>
            <tr>
                <th>Depth</th>
                <th>URL</th>
                <th>Category</th>
                <th>Purpose</th>
                <th>Inputs</th>
                <th>Sensitive</th>
            </tr>
        </thead>
        <tbody>
        {% for page in site_map.pages[:50] %}
            <tr>
                <td style="text-align:center;">{{ page.depth }}</td>
                <td class="endpoint-url" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ page.url[:80] }}</td>
                <td><span class="inv-cat-badge inv-cat-{{ page.page_category }}">{{ page.page_category }}</span></td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ page.page_purpose[:60] }}</td>
                <td>{{ page.input_fields | length }}</td>
                <td>{% if page.sensitive_data_visible %}<span class="sensitive-badge">SENSITIVE</span>{% endif %}</td>
            </tr>
        {% endfor %}
        {% if site_map.pages | length > 50 %}
            <tr><td colspan="6" style="text-align:center;color:var(--text-muted);">... and {{ site_map.pages | length - 50 }} more pages</td></tr>
        {% endif %}
        </tbody>
    </table>
    {% endif %}
</div>
{% endif %}

<!-- Role Comparison Analysis (V3.0) -->
{% if feature_inventory and feature_inventory.role_differences and feature_inventory.role_differences.comparison %}
<h2 class="section-title">Role Comparison Analysis</h2>
<div class="inventory-section">
    <div class="inventory-grid">
        {% set comp = feature_inventory.role_differences.comparison %}
        {% set role_names = [] %}
        {% for key in feature_inventory.role_differences.keys() %}
            {% if key != 'comparison' %}
                {% set _ = role_names.append(key) %}
            {% endif %}
        {% endfor %}

        {% if role_names | length >= 1 %}
        <div class="inventory-stat">
            <span class="num">{{ feature_inventory.role_differences[role_names[0]].total_pages }}</span>
            <span class="lbl">{{ role_names[0] }} Pages</span>
        </div>
        {% endif %}
        {% if role_names | length >= 2 %}
        <div class="inventory-stat">
            <span class="num">{{ feature_inventory.role_differences[role_names[1]].total_pages }}</span>
            <span class="lbl">{{ role_names[1] }} Pages</span>
        </div>
        {% endif %}
        <div class="inventory-stat">
            <span class="num">{{ comp.pages_visible_to_both }}</span>
            <span class="lbl">Shared Pages</span>
        </div>
        <div class="inventory-stat">
            <span class="num" style="color:var(--accent-red);">{{ comp.access_difference_count }}</span>
            <span class="lbl">Access Differences</span>
        </div>
    </div>

    <table class="inventory-table">
        <thead>
            <tr>
                <th>Page / Feature</th>
                {% for rn in role_names %}
                <th>{{ rn | title }}</th>
                {% endfor %}
                <th>Risk Assessment</th>
            </tr>
        </thead>
        <tbody>
        {% for page in site_map.pages[:40] %}
            <tr>
                <td class="endpoint-url" style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{{ page.url[:70] }}</td>
                {% for rn in role_names %}
                <td>
                    {% set role_pages = [] %}
                    {% for p in site_map.pages %}
                        {% if feature_inventory.role_differences.get(rn, {}).get('total_pages', 0) > 0 %}
                            {# Simple heuristic: page exists in this role's site map if it was discovered #}
                            &#x2713;
                        {% endif %}
                    {% endfor %}
                </td>
                {% endfor %}
                <td>
                    {% if page.page_category == 'admin' %}
                    <span class="risk-tag risk-sqli">ADMIN ACCESS</span>
                    {% elif page.sensitive_data_visible %}
                    <span class="risk-tag risk-xss">SENSITIVE DATA</span>
                    {% else %}
                    <span class="risk-tag risk-none">REVIEW</span>
                    {% endif %}
                </td>
            </tr>
        {% endfor %}
        </tbody>
    </table>

    {% if comp.pages_only_visible_to_0 is defined and comp.pages_only_visible_to_0 %}
    <h3 style="font-size:13px;color:var(--text-secondary);margin:16px 0 8px;">Pages Only Visible to First Role</h3>
    <ul style="font-size:12px;color:var(--text-primary);list-style:none;padding:0;">
    {% for url in comp.pages_only_visible_to_0[:20] %}
        <li style="padding:4px 0;border-bottom:1px solid var(--border);"><span class="inv-cat-badge inv-cat-admin" style="font-size:9px;">EXCLUSIVE</span> {{ url[:80] }}</li>
    {% endfor %}
    </ul>
    {% endif %}

    {% if comp.pages_only_visible_to_1 is defined and comp.pages_only_visible_to_1 %}
    <h3 style="font-size:13px;color:var(--text-secondary);margin:16px 0 8px;">Pages Only Visible to Second Role</h3>
    <ul style="font-size:12px;color:var(--text-primary);list-style:none;padding:0;">
    {% for url in comp.pages_only_visible_to_1[:20] %}
        <li style="padding:4px 0;border-bottom:1px solid var(--border);"><span class="inv-cat-badge inv-cat-list_view" style="font-size:9px;">EXCLUSIVE</span> {{ url[:80] }}</li>
    {% endfor %}
    </ul>
    {% endif %}
</div>
{% endif %}

<!-- Discovered Business Workflows (V3.1) -->
{% if workflows %}
<h2 class="section-title">Discovered Business Workflows</h2>
<div class="workflows-section">
{% for wf in workflows %}
<div class="workflow-card">
    <div class="workflow-header">
        <span class="workflow-badge">{{ wf.detected_via }}</span>
        <span class="workflow-name">{{ wf.name }}</span>
        <span class="confidence-badge">Confidence: {{ "%.0f"|format(wf.confidence * 100) }}%</span>
    </div>

    <!-- State Machine Flowchart -->
    <div class="workflow-flowchart">
        {% for step in wf.steps %}
        <div class="workflow-step">
            <div class="step-number">{{ step.step_number }}</div>
            <div class="step-action">{{ step.action_description[:40] }}</div>
            <div class="step-url">{{ step.url[:50] }}{% if step.url|length > 50 %}...{% endif %}</div>
            {% if step.state_parameters %}
            <div class="step-params">State: {{ step.state_parameters | join(', ') }}</div>
            {% endif %}
        </div>
        {% if not loop.last %}
        <div class="workflow-arrow">&#x2192;</div>
        {% endif %}
        {% endfor %}
    </div>

    <!-- API6 Test Results -->
    {% if wf.api6_test_results %}
    <div class="workflow-results">
        <h4>API6 Test Results</h4>
        {% for test_id, result in wf.api6_test_results.items() %}
        <div class="workflow-test-result">
            <span class="workflow-test-id">{{ test_id }}</span>
            {% if result == 'PASS' %}
            <span class="workflow-result-badge workflow-result-pass">PASS</span>
            {% elif result == 'FAIL' %}
            <span class="workflow-result-badge workflow-result-fail">FAIL</span>
            {% else %}
            <span class="workflow-result-badge workflow-result-na">N/A</span>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}
</div>
{% endfor %}
</div>
{% else %}
<div class="workflows-section">
    <div class="workflow-empty">
        No multi-step business workflows (Salesforce Flows, Wizards) were detected during autonomous reconnaissance.
    </div>
</div>
{% endif %}

<!-- OWASP Compliance Coverage Matrix -->
<h2 class="section-title">OWASP Compliance Coverage Matrix</h2>
<div class="compliance-section">
{% for std_key, std in compliance_data.items() %}
<div class="compliance-standard">
    <div class="compliance-standard-header" onclick="toggleCompliance('{{ std_key }}')">
        <div style="display:flex;align-items:center;gap:12px;">
            <button class="toggle-btn" id="cov-toggle-{{ std_key }}">&#x25B6;</button>
            <h3>{{ std.full_name }}</h3>
        </div>
        <span class="std-short">{{ std.short_name }}</span>
    </div>
    <div id="cov-details-{{ std_key }}" style="display:none;">
    <table class="compliance-table">
        <thead>
            <tr>
                <th style="text-align:left;">Category</th>
                <th>Total</th>
                <th>Executed</th>
                <th>Passed</th>
                <th>Findings</th>
                <th>N/A</th>
                <th>Errors</th>
                <th class="cov-cell">Coverage</th>
            </tr>
        </thead>
        <tbody>
        {% for cat in std.rows %}
            <tr>
                <td>
                    <span class="cat-code">{{ cat.code }}</span>
                    <span class="cat-name">&mdash; {{ cat.name }}</span>
                </td>
                <td><span class="cnt-badge cnt-total">{{ cat.total }}</span></td>
                <td><span class="cnt-badge cnt-total">{{ cat.executed }}</span></td>
                <td><span class="cnt-badge cnt-passed">{{ cat.passed }}</span></td>
                <td><span class="cnt-badge cnt-finding">{{ cat.findings }}</span></td>
                <td><span class="cnt-badge cnt-na">{{ cat.na }}</span></td>
                <td><span class="cnt-badge cnt-error">{{ cat.errors }}</span></td>
                <td class="cov-cell">
                    <div class="cov-bar-wrap">
                        <div class="cov-bar">
                            <div class="cov-bar-fill {{ cat.cov_class }}" style="width:{{ cat.coverage }}%"></div>
                        </div>
                        <span class="cov-pct {{ cat.cov_pct_class }}">{{ cat.coverage }}%</span>
                    </div>
                </td>
            </tr>
        {% endfor %}
            <tr class="compliance-total">
                <td>TOTAL</td>
                <td><span class="cnt-badge cnt-total">{{ std.totals.total }}</span></td>
                <td><span class="cnt-badge cnt-total">{{ std.totals.executed }}</span></td>
                <td><span class="cnt-badge cnt-passed">{{ std.totals.passed }}</span></td>
                <td><span class="cnt-badge cnt-finding">{{ std.totals.findings }}</span></td>
                <td><span class="cnt-badge cnt-na">{{ std.totals.na }}</span></td>
                <td><span class="cnt-badge cnt-error">{{ std.totals.errors }}</span></td>
                <td class="cov-cell">
                    <div class="cov-bar-wrap">
                        <div class="cov-bar">
                            <div class="cov-bar-fill {{ std.totals.cov_class }}" style="width:{{ std.totals.coverage }}%"></div>
                        </div>
                        <span class="cov-pct {{ std.totals.cov_pct_class }}">{{ std.totals.coverage }}%</span>
                    </div>
                </td>
            </tr>
        </tbody>
    </table>
    </div>
</div>
{% endfor %}
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

        <!-- Visual DAST Evidence (V3.0) - outside f.evidence block -->
        {% if f.visual_verdict %}
        <div class="detail-section">
            <h4>Visual DAST Analysis</h4>
            <div class="visual-evidence">
                {% if f.evidence and f.evidence.screenshot_path %}
                <div class="visual-evidence-img">
                    <img src="{{ f.evidence.screenshot_path }}" alt="Visual DAST Screenshot" loading="lazy" onclick="window.open(this.src, '_blank')">
                </div>
                {% endif %}
                <div class="visual-evidence-text">
                    <span class="visual-verdict-badge vv-{{ f.visual_verdict|lower }}">{{ f.visual_verdict | replace('_', ' ') }}</span>
                    {% if f.visual_confidence is not none %}
                    <span class="confidence-badge" style="margin-left:6px;">Confidence: {{ "%.0f"|format(f.visual_confidence * 100) }}%</span>
                    {% endif %}
                    {% if f.visual_reasoning %}
                    <div class="visual-evidence-label">Reasoning</div>
                    <div class="visual-evidence-content">{{ f.visual_reasoning }}</div>
                    {% endif %}
                    {% if f.visible_evidence %}
                    <div class="visual-evidence-label">Visible Evidence</div>
                    <div class="visual-evidence-content">{{ f.visible_evidence }}</div>
                    {% endif %}
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Evidence Checklist (V4.0) -->
        {% if f.evidence_required is defined and f.evidence_required %}
        <div class="detail-section">
            <h4>Evidence Checklist</h4>
            <div class="evidence-checklist">
                {% for ev_type in f.evidence_required %}
                <div class="evidence-item">
                    {% if ev_type in f.evidence_captured %}
                    <span class="evidence-captured">&#x2705;</span>
                    {% else %}
                    <span class="evidence-missing">&#x274C;</span>
                    {% endif %}
                    <span>{{ ev_type }}</span>
                </div>
                {% endfor %}
            </div>
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

function toggleCompliance(stdKey) {
    const el = document.getElementById('cov-details-' + stdKey);
    const btn = document.getElementById('cov-toggle-' + stdKey);
    if (el.style.display === 'none') {
        el.style.display = 'block';
        btn.classList.add('open');
    } else {
        el.style.display = 'none';
        btn.classList.remove('open');
    }
}

function toggleTreeNode(nodeId) {
    const children = document.getElementById('tree-children-' + nodeId);
    const btn = document.getElementById('tree-btn-' + nodeId);
    if (!children) return;
    if (children.style.display === 'none') {
        children.style.display = 'block';
        btn.innerHTML = '&#x25BC;';
    } else {
        children.style.display = 'none';
        btn.innerHTML = '&#x25B6;';
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
        # Build compliance matrix for JSON export
        compliance_matrix = self._build_compliance_matrix(report.all_results)

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
            "owasp_compliance_matrix": compliance_matrix,
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

        # Build OWASP Compliance Coverage Matrix
        compliance_data = self._build_compliance_matrix(report.all_results)

        # Extract workflows from feature inventory
        workflows = []
        if report.feature_inventory and report.feature_inventory.workflows:
            workflows = report.feature_inventory.workflows

        html_content = template.render(
            report=report,
            summary=report.executive_summary,
            findings_list=all_findings,
            compliance_data=compliance_data,
            site_map=report.site_map,
            feature_inventory=report.feature_inventory,
            workflows=workflows,
        )

        html_path = self.output_dir / "security_report.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return html_path

    # ------------------------------------------------------------------
    # OWASP Compliance Coverage Matrix
    # ------------------------------------------------------------------
    def _build_compliance_matrix(
        self, all_results: list[FindingResult]
    ) -> dict[str, dict[str, Any]]:
        """Build the compliance coverage matrix from all test results.

        Groups results by OWASP standard and category, then calculates
        executed/passed/finding/na/error counts and coverage percentage.
        """
        # Count results per (standard_key, category_code)
        counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
            lambda: {"executed": 0, "passed": 0, "findings": 0, "na": 0, "errors": 0}
        )

        for result in all_results:
            # Determine which standard this result belongs to
            cat = result.owasp_category or ""
            std_key = self._categorise_to_standard(cat)

            # Extract category code (e.g. "API1", "A03", "5.1")
            code = self._extract_category_code(cat, std_key)
            if code:
                bucket = counts[(std_key, code)]
                bucket["executed"] += 1
                if result.verdict == FindingVerdict.NOT_FINDING:
                    bucket["passed"] += 1
                elif result.verdict == FindingVerdict.FINDING:
                    bucket["findings"] += 1
                elif result.verdict == FindingVerdict.NA:
                    bucket["na"] += 1
                elif result.verdict == FindingVerdict.ERROR:
                    bucket["errors"] += 1

        # Build output structure
        output: dict[str, dict[str, Any]] = {}

        for std_key, std_meta in _OWASP_STANDARDS.items():
            rows = []
            totals = {"total": 0, "executed": 0, "passed": 0, "findings": 0, "na": 0, "errors": 0}

            for cat_code, cat_name in std_meta["categories"]:
                c = counts.get((std_key, cat_code), {})
                executed = c.get("executed", 0)
                passed = c.get("passed", 0)
                findings = c.get("findings", 0)
                na = c.get("na", 0)
                errors = c.get("errors", 0)

                # Coverage = (passed + findings + na) / executed * 100
                # If nothing was executed, coverage is 0
                meaningful = passed + findings + na
                coverage = round(meaningful / executed * 100) if executed > 0 else 0

                cov_class, cov_pct_class = self._coverage_classes(coverage)

                rows.append({
                    "code": cat_code,
                    "name": cat_name,
                    "total": executed,  # total defined = executed for display
                    "executed": executed,
                    "passed": passed,
                    "findings": findings,
                    "na": na,
                    "errors": errors,
                    "coverage": coverage,
                    "cov_class": cov_class,
                    "cov_pct_class": cov_pct_class,
                })

                totals["total"] += executed
                totals["executed"] += executed
                totals["passed"] += passed
                totals["findings"] += findings
                totals["na"] += na
                totals["errors"] += errors

            # Compute totals coverage
            total_meaningful = totals["passed"] + totals["findings"] + totals["na"]
            totals["coverage"] = (
                round(total_meaningful / totals["executed"] * 100)
                if totals["executed"] > 0
                else 0
            )
            totals["cov_class"], totals["cov_pct_class"] = self._coverage_classes(
                totals["coverage"]
            )

            output[std_key] = {
                "full_name": std_meta["full_name"],
                "short_name": std_meta["short_name"],
                "rows": rows,
                "totals": totals,
            }

        return output

    @staticmethod
    def _categorise_to_standard(owasp_category: str) -> str:
        """Map an owasp_category string to its standard key."""
        cat_upper = owasp_category.upper()
        if cat_upper.startswith("API"):
            return "owasp_api_2023"
        if cat_upper.startswith("A0") or cat_upper.startswith("A1"):
            return "owasp_web_2021"
        if cat_upper.startswith("SCP"):
            return "owasp_scp_v2"
        if "." in owasp_category and owasp_category[0].isdigit():
            return "owasp_scp_v2"
        # Heuristic fallback based on name keywords
        cat_lower = owasp_category.lower()
        if "api" in cat_lower:
            return "owasp_api_2023"
        if "scg" in cat_lower or "scp" in cat_lower or "secure" in cat_lower or "input" in cat_lower:
            return "owasp_scp_v2"
        return "owasp_web_2021"

    @staticmethod
    def _extract_category_code(owasp_category: str, std_key: str) -> str | None:
        """Extract the category code from the owasp_category string.

        Examples:
            'API1:2023' -> 'API1'
            'A03:2021'  -> 'A03'
            'SCP-01'    -> 'SCP-01'
            'SCG-InputValidation' -> 'SCG-InputValidation' (legacy)
            '5.1'       -> '5.1'
        """
        cat = owasp_category.strip()

        # SCP-XX format (new v2 mapping)
        if cat.upper().startswith("SCP"):
            return cat.split(":")[0]

        # Direct code (e.g. "API1", "A03")
        if cat[:3] in ("API", "api"):
            return cat.split(":")[0].split("-")[0].split(" ")[0].upper()
        if len(cat) >= 3 and cat[0] == "A" and cat[1].isdigit():
            return cat.split(":")[0].split("-")[0].split(" ")[0].upper()

        # SCG-style: extract the numeric part (e.g. "SCG-InputValidation" -> "5.1" or "SCG-IV")
        parts = cat.split("-")
        if len(parts) >= 2:
            # Try to find a matching code in the standard's categories
            search = parts[0].strip().upper()
            if std_key in _OWASP_STANDARDS:
                for code, _ in _OWASP_STANDARDS[std_key]["categories"]:
                    if code.upper() == search:
                        return code
            # Fallback: return the first part
            return parts[0].strip()

        # Bare number like "5.1"
        if "." in cat and cat[0].isdigit():
            return cat

        return cat.split(":")[0] if cat else None

    @staticmethod
    def _coverage_classes(coverage: int) -> tuple[str, str]:
        """Return (bar_css_class, pct_css_class) for a coverage percentage."""
        if coverage >= 100:
            return "cov-100", "pct-100"
        if coverage >= 75:
            return "cov-high", "pct-high"
        if coverage >= 50:
            return "cov-med", "pct-med"
        if coverage > 0:
            return "cov-low", "pct-low"
        return "cov-zero", "pct-zero"

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
