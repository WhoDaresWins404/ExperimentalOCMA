import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import ScanResult, ScanSummary, Finding, Endpoint


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowRecon Report - {target}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #0d1b2a 0%, #1b2838 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; border: 1px solid #1e3a5f; }}
.header h1 {{ color: #00e5ff; font-size: 2em; }}
.header .meta {{ color: #8899aa; margin-top: 10px; font-size: 0.9em; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 15px; margin-bottom: 30px; }}
.summary-card {{ background: #111927; border-radius: 8px; padding: 20px; border: 1px solid #1e3a5f; text-align: center; }}
.summary-card .number {{ font-size: 2.5em; font-weight: bold; }}
.summary-card .label {{ color: #8899aa; font-size: 0.85em; text-transform: uppercase; margin-top: 5px; }}
.critical {{ color: #ff1744; }} .high {{ color: #ff9100; }} .medium {{ color: #ffd600; }} .low {{ color: #00e5ff; }}
.severity-bar {{ display: flex; height: 24px; border-radius: 12px; overflow: hidden; margin-bottom: 25px; }}
.severity-bar .seg {{ display: flex; align-items: center; justify-content: center; font-size: 0.75em; font-weight: bold; color: #000; transition: flex 0.3s; }}
.section {{ background: #111927; border-radius: 8px; padding: 25px; margin-bottom: 30px; border: 1px solid #1e3a5f; }}
.section h2 {{ color: #00e5ff; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #1e3a5f; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #1e3a5f; }}
th {{ color: #00e5ff; font-size: 0.85em; text-transform: uppercase; }}
tr:hover {{ background: rgba(0, 229, 255, 0.05); }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
.badge-critical {{ background: #ff1744; color: #fff; }}
.badge-high {{ background: #ff9100; color: #000; }}
.badge-medium {{ background: #ffd600; color: #000; }}
.badge-low {{ background: #00e5ff; color: #000; }}
.badge-info {{ background: #2979ff; color: #fff; }}
.evidence {{ background: #0a0e17; padding: 15px; border-radius: 5px; font-family: 'Cascadia Code', monospace; font-size: 0.85em; overflow-x: auto; white-space: pre-wrap; margin-top: 10px; max-height: 300px; overflow-y: auto; }}
.cvss-score-bar {{ display: flex; align-items: center; gap: 8px; margin: 5px 0; }}
.cvss-score-bar .track {{ flex: 1; height: 8px; background: #0a0e17; border-radius: 4px; overflow: hidden; }}
.cvss-score-bar .fill {{ height: 100%; border-radius: 4px; transition: width 0.5s; }}
.cvss-vector {{ font-family: 'Cascadia Code', monospace; font-size: 0.8em; color: #8899aa; background: #0a0e17; padding: 4px 8px; border-radius: 4px; display: inline-block; }}
.priority-high {{ color: #ff1744; }} .priority-med {{ color: #ffd600; }} .priority-low {{ color: #00e5ff; }}
.timeline {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }}
.timeline-item {{ background: #0a0e17; border-radius: 6px; padding: 12px 16px; border-left: 3px solid #00e5ff; flex: 1; min-width: 140px; }}
.timeline-item .tl-label {{ color: #8899aa; font-size: 0.8em; text-transform: uppercase; }}
.timeline-item .tl-value {{ font-size: 1.2em; font-weight: bold; }}
.chain-group {{ margin-bottom: 20px; }}
.chain-group h3 {{ color: #00e5ff; font-size: 1em; margin-bottom: 10px; }}
.chain-link {{ display: inline-block; background: #0a0e17; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; color: #8899aa; }}
.finding-card {{ background: #0f1a2e; padding: 15px; border-radius: 6px; margin-bottom: 15px; border-left: 4px solid #2979ff; }}
.finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }}
.finding-meta {{ color: #8899aa; font-size: 0.9em; margin-bottom: 10px; }}
.evasion-table {{ width: 100%; margin-top: 10px; font-size: 0.9em; }}
.evasion-table th {{ font-size: 0.8em; }}
.success {{ color: #00e676; }} .failure {{ color: #ff1744; }}
.footer {{ text-align: center; color: #556677; padding: 20px; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>ShadowRecon Security Report</h1>
<div class="meta">
Target: <strong>{target}</strong><br>
Scan Date: {scan_date}<br>
Duration: {duration}s | Session: {session_id}
</div>
</div>

{severity_bar}

<div class="summary-grid">
<div class="summary-card"><div class="number critical">{critical}</div><div class="label">Critical</div></div>
<div class="summary-card"><div class="number high">{high}</div><div class="label">High</div></div>
<div class="summary-card"><div class="number medium">{medium}</div><div class="label">Medium</div></div>
<div class="summary-card"><div class="number low">{low}</div><div class="label">Low</div></div>
<div class="summary-card"><div class="number">{total_endpoints}</div><div class="label">Endpoints</div></div>
<div class="summary-card"><div class="number">{total_findings}</div><div class="label">Total Findings</div></div>
</div>

{phase_timeline}

<div class="section">
<h2>Attack Path Chains</h2>
{attack_chain_content}
</div>

<div class="section">
<h2>Endpoints Found</h2>
<table>
<tr><th>URL</th><th>Method</th><th>Type</th><th>Status</th><th>Size</th><th>Content Type</th><th>Discovered By</th></tr>
{endpoint_rows}
</table>
</div>

<div class="section">
<h2>Findings</h2>
{finding_cards}
</div>

<div class="section">
<h2>Endpoints by Type</h2>
<table>
<tr><th>Type</th><th>Count</th></tr>
{type_rows}
</table>
</div>

<div class="section">
<h2>Top Risks</h2>
{top_risks_content}
</div>

{llm_summary_section}

<div class="footer">
Generated by ShadowRecon on {generated_at}
</div>
</div>
</body>
</html>"""


class ReportGenerator:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate_html(self, result: ScanResult, summary: ScanSummary) -> str:
        severity_colors = {
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "none": "info", "info": "info",
        }
        sv = lambda f: f.severity.value if hasattr(f.severity, "value") else str(f.severity)

        total = summary.critical_count + summary.high_count + summary.medium_count + summary.low_count
        if total > 0:
            bar = (
                f'<div class="severity-bar">'
                f'<div class="seg" style="flex:{summary.critical_count};background:#ff1744">{summary.critical_count}</div>'
                f'<div class="seg" style="flex:{summary.high_count};background:#ff9100">{summary.high_count}</div>'
                f'<div class="seg" style="flex:{summary.medium_count};background:#ffd600">{summary.medium_count}</div>'
                f'<div class="seg" style="flex:{summary.low_count};background:#00e5ff">{summary.low_count}</div>'
                f'</div>'
            )
        else:
            bar = ""

        timeline = ""
        if result.started_at:
            start = result.started_at
            ended = result.ended_at or datetime.utcnow()
            timeline = (
                f'<div class="section">'
                f'<h2>Scan Timeline</h2>'
                f'<div class="timeline">'
                f'<div class="timeline-item"><div class="tl-label">Start</div><div class="tl-value">{start.strftime("%H:%M:%S")}</div></div>'
                f'<div class="timeline-item"><div class="tl-label">End</div><div class="tl-value">{ended.strftime("%H:%M:%S")}</div></div>'
                f'<div class="timeline-item" style="border-left-color:#ffd600"><div class="tl-label">Duration</div><div class="tl-value">{summary.scan_duration_seconds}s</div></div>'
                f'<div class="timeline-item" style="border-left-color:#ff9100"><div class="tl-label">Findings/sec</div><div class="tl-value">{summary.total_findings / max(summary.scan_duration_seconds, 1):.2f}</div></div>'
                f'</div></div>'
            )

        scanner_finding_map = {}
        for f in result.findings:
            sn = f.scanner_name
            if sn not in scanner_finding_map:
                scanner_finding_map[sn] = []
            scanner_finding_map[sn].append(f)
        attack_chain = ""
        scanner_labels = {
            "api_scanner": "API probing",
            "directory_scanner": "Directory brute-force",
            "misconfig_scanner": "Misconfiguration check",
            "anomaly_detector": "Anomaly detection",
            "waf_detector": "WAF detection",
        }
        for scanner, finds in scanner_finding_map.items():
            label = scanner_labels.get(scanner, scanner)
            endpoints_for_scanner = [ep for ep in result.endpoints if ep.discovered_by == scanner]
            attack_chain += f'<div class="chain-group"><h3>{label} ({len(finds)})</h3>'
            if endpoints_for_scanner:
                attack_chain += '<div style="margin-bottom:8px">Endpoints: '
                for ep in endpoints_for_scanner:
                    attack_chain += f'<span class="chain-link">{ep.url}</span> '
                attack_chain += "</div>"
            attack_chain += "<ul>"
            for f in finds[:5]:
                prio = f.cvss_score * f.confidence if f.cvss_score else 0
                attack_chain += f'<li style="margin-bottom:4px"><span class="badge badge-{severity_colors.get(sv(f), "info")}" style="margin-right:6px">{sv(f).upper()}</span>{f.title} <span class="chain-link">priority: {prio:.1f}</span></li>'
            if len(finds) > 5:
                attack_chain += f"<li>... and {len(finds)-5} more</li>"
            attack_chain += "</ul></div>"

        endpoint_rows = ""
        for ep in sorted(result.endpoints, key=lambda x: x.url):
            ep_type = ep.type.value if hasattr(ep.type, "value") else str(ep.type)
            size_str = f"{ep.response_size}" if ep.response_size else "-"
            if ep.response_size and ep.response_size > 1024:
                size_str = f"{ep.response_size/1024:.1f}KB"
            ct = ep.content_type or "-"
            endpoint_rows += (
                f"<tr><td>{ep.url}</td><td>{ep.method}</td>"
                f"<td>{ep_type}</td><td>{ep.status_code or '-'}</td>"
                f"<td>{size_str}</td><td>{ct}</td>"
                f"<td>{ep.discovered_by}</td></tr>\n"
            )

        finding_cards = ""
        sorted_findings = sorted(result.findings, key=lambda x: (x.cvss_score or 0) * x.confidence, reverse=True)
        for finding in sorted_findings:
            badge_class = severity_colors.get(sv(finding), "info")
            evidence_html = json.dumps(finding.evidence, indent=2)[:2000] if finding.evidence else "N/A"
            remediation = finding.remediation or "Not specified"
            prio_score = (finding.cvss_score or 0) * finding.confidence
            prio_class = "priority-high" if prio_score >= 7 else ("priority-med" if prio_score >= 4 else "priority-low")

            cvss_html = ""
            cvss_score = finding.cvss_score
            if cvss_score is not None:
                score_pct = min(cvss_score / 10 * 100, 100)
                score_color = "#ff1744" if cvss_score >= 9 else "#ff9100" if cvss_score >= 7 else "#ffd600" if cvss_score >= 4 else "#00e5ff"
                cvss_html = f'<div class="cvss-score-bar">CVSS: <strong>{cvss_score}</strong><div class="track"><div class="fill" style="width:{score_pct:.0f}%;background:{score_color}"></div></div></div>'
            if finding.cvss_vector:
                cvss_html += f'<div class="cvss-vector">{finding.cvss_vector.vector_string()}</div>'

            evasion_html = ""
            if finding.evidence and "results" in finding.evidence:
                rows = ""
                for r in finding.evidence["results"]:
                    icon = "&#10003;" if r["success"] else "&#10007;"
                    cls = "success" if r["success"] else "failure"
                    rows += f"<tr><td>{r['probe']}</td><td>{r['original_status']}</td><td>{r['evaded_status']}</td><td class=\"{cls}\">{icon}</td></tr>"
                evasion_html = f'<table class="evasion-table"><tr><th>Probe</th><th>Original</th><th>Evaded</th><th>Bypass</th></tr>{rows}</table>'

            llm_enhance = ""
            if finding.is_llm_enhanced and finding.llm_analysis:
                la = finding.llm_analysis
                llm_enhance = (
                    f'<div style="margin-top:10px;background:#0a0e17;padding:12px;border-radius:4px;border-left:2px solid #7c4dff">'
                    f'<div style="color:#7c4dff;font-size:0.8em;text-transform:uppercase;margin-bottom:4px">LLM Analysis ({la.model_used})</div>'
                    f'<p style="font-size:0.9em">{la.natural_description}</p>'
                    f'<div style="margin-top:6px;font-size:0.85em"><strong>Impact:</strong> {la.impact_analysis}</div>'
                    f'</div>'
                )

            border_colors = {"critical": "#ff1744", "high": "#ff9100", "medium": "#ffd600", "low": "#00e5ff", "info": "#2979ff", "none": "#2979ff"}
            finding_cards += f"""
            <div class="finding-card" style="border-left-color:{border_colors.get(badge_class, '#2979ff')}">
                <div class="finding-header">
                    <strong style="font-size:1.1em;">{finding.title}</strong>
                    <span class="badge badge-{badge_class}">{sv(finding).upper()}</span>
                </div>
                <div class="finding-meta">
                    Scanner: {finding.scanner_name} | CVSS: {finding.cvss_score or 'N/A'} | Confidence: {finding.confidence:.0%} | <span class="{prio_class}">Priority: {prio_score:.1f}</span>
                </div>
                {cvss_html}
                <p>{finding.description}</p>
                <div style="margin-top:10px;">
                    <strong>Remediation:</strong> {remediation}
                </div>
                {evasion_html}
                {llm_enhance}
                <div class="evidence">{evidence_html}</div>
            </div>
            """

        type_rows = ""
        for ep_type, count in sorted(summary.endpoints_by_type.items(), key=lambda x: -x[1]):
            type_rows += f"<tr><td>{ep_type}</td><td>{count}</td></tr>\n"

        top_risks_content = ""
        if summary.top_risks:
            top_risks_content = "<ul>" + "".join(f"<li>{risk}</li>" for risk in summary.top_risks) + "</ul>"
        else:
            top_risks_content = "<p>No critical or high-risk findings.</p>"

        llm_summary_section = ""
        if summary.llm_summary:
            llm_summary_section = f"""
            <div class="section">
            <h2>LLM Executive Summary</h2>
            <div style="color: #e0e0e0; line-height: 1.8;">{summary.llm_summary}</div>
            </div>
            """

        return HTML_TEMPLATE.format(
            target=result.target,
            scan_date=result.started_at.isoformat() if result.started_at else "N/A",
            duration=summary.scan_duration_seconds,
            session_id=result.session_id[:12],
            critical=summary.critical_count,
            high=summary.high_count,
            medium=summary.medium_count,
            low=summary.low_count,
            total_endpoints=summary.total_endpoints,
            total_findings=summary.total_findings,
            severity_bar=bar,
            phase_timeline=timeline,
            attack_chain_content=attack_chain,
            endpoint_rows=endpoint_rows,
            finding_cards=finding_cards,
            type_rows=type_rows,
            top_risks_content=top_risks_content,
            generated_at=datetime.utcnow().isoformat(),
            llm_summary_section=llm_summary_section,
        )

    def save_html(self, html: str, session_id: str) -> str:
        path = os.path.join(self.output_dir, f"shadowrecon_report_{session_id[:12]}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def generate_json(self, result: ScanResult, summary: ScanSummary) -> str:
        findings_out = []
        for f in result.findings:
            fd = f.model_dump()
            fd["remediation_priority_score"] = round((f.cvss_score or 0) * f.confidence, 2)
            fd["cvss_vector_string"] = f.cvss_vector.vector_string() if f.cvss_vector else None
            findings_out.append(fd)

        data = {
            "report_version": "1.1",
            "tool": "ShadowRecon",
            "target": result.target,
            "session_id": result.session_id,
            "scan_date": result.started_at.isoformat() if result.started_at else None,
            "duration_seconds": summary.scan_duration_seconds,
            "severity_distribution": {
                "critical": summary.critical_count,
                "high": summary.high_count,
                "medium": summary.medium_count,
                "low": summary.low_count,
            },
            "summary": summary.model_dump(),
            "endpoints": [
                {
                    **ep.model_dump(),
                    "size_display": f"{ep.response_size/1024:.1f}KB" if ep.response_size and ep.response_size > 1024 else str(ep.response_size) if ep.response_size else None,
                }
                for ep in result.endpoints
            ],
            "findings": findings_out,
        }
        return json.dumps(data, indent=2, default=str)

    def save_json(self, json_str: str, session_id: str) -> str:
        path = os.path.join(self.output_dir, f"shadowrecon_report_{session_id[:12]}.json")
        with open(path, "w") as f:
            f.write(json_str)
        return path

    def generate_all(self, result: ScanResult, summary: ScanSummary) -> dict[str, str]:
        html = self.generate_html(result, summary)
        html_path = self.save_html(html, result.session_id)
        json_str = self.generate_json(result, summary)
        json_path = self.save_json(json_str, result.session_id)
        return {"html": html_path, "json": json_path}
