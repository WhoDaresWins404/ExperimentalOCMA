def format_findings_for_summary(result) -> dict:
    summary = result.stats if hasattr(result, "stats") else {}
    findings = getattr(result, "findings", [])
    endpoints = getattr(result, "endpoints", [])

    scanners = summary.get("findings_by_scanner", {}) or {}
    if not scanners and findings:
        for f in findings:
            sn = f.scanner_name
            scanners[sn] = scanners.get(sn, 0) + 1

    by_type = summary.get("endpoints_by_type", {}) or {}
    if not by_type and endpoints:
        for ep in endpoints:
            t = ep.type.value if hasattr(ep.type, "value") else str(ep.type)
            by_type[t] = by_type.get(t, 0) + 1

    findings_by_scanner = "\n".join(
        f"  - {scanner}: {count} findings"
        for scanner, count in sorted(scanners.items())
    ) or "  (none)"

    endpoints_by_type = "\n".join(
        f"  - {ep_type}: {count}"
        for ep_type, count in sorted(by_type.items(), key=lambda x: -x[1])
    ) or "  (none)"

    waf_name = "none"
    for f in findings:
        if "waf" in f.tags and f.evidence.get("waf_name"):
            waf_name = f.evidence["waf_name"]
            break

    finding_lines = []
    for f in sorted(findings, key=lambda x: x.cvss_score or 0, reverse=True):
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        cvss = f"CVSS:{f.cvss_score:.1f}" if f.cvss_score else "CVSS:N/A"
        desc = (f.description or "")[:200].replace("\n", " ")
        finding_lines.append(f"  [{sev.upper()}] {f.title} ({cvss}, scanner: {f.scanner_name})")
        if desc:
            finding_lines.append(f"    {desc}")
    finding_text = "\n".join(finding_lines) if finding_lines else "  (none)"

    return {
        "waf_detected": waf_name,
        "findings_by_scanner": findings_by_scanner,
        "endpoints_by_type": endpoints_by_type,
        "finding_lines": finding_text,
    }


def format_llm_section(value) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                lines = []
                for k, v in item.items():
                    k_clean = k.replace("_", " ").title()
                    if isinstance(v, list):
                        v = ", ".join(str(x) for x in v)
                    lines.append(f"  {k_clean}: {v}")
                parts.append("\n".join(lines))
            else:
                parts.append(f"  - {item}")
        return "\n".join(parts)
    if isinstance(value, dict):
        if "findings" in value and isinstance(value["findings"], list):
            return format_llm_section(value["findings"])
        if "steps" in value and isinstance(value["steps"], list):
            return format_llm_section(value["steps"])
        if "actions" in value and isinstance(value["actions"], list):
            return format_llm_section(value["actions"])
        lines = []
        for k, v in value.items():
            k_clean = k.replace("_", " ").title()
            if isinstance(v, list):
                lines.append(f"{k_clean}:")
                for item in v:
                    if isinstance(item, dict):
                        lines.append(f"  - {item.get('step', item.get('what_to_fix', item.get('description', str(item))))}")
                    else:
                        lines.append(f"  - {item}")
            elif isinstance(v, dict):
                lines.append(f"{k_clean}:")
                for sk, sv in v.items():
                    lines.append(f"  {sk}: {sv}")
            else:
                lines.append(f"{k_clean}: {v}")
        return "\n".join(lines)
    return str(value)


FINDING_ENRICHMENT_PROMPT = """You are a senior cybersecurity analyst. Analyze the following finding from a security scan and provide a detailed assessment.

FINDING:
Title: {title}
Description: {description}
Severity: {severity}
Scanner: {scanner_name}
Endpoint: {endpoint_url}
Evidence: {evidence_json}

Please provide:
1. **Natural Language Description**: Explain the finding in clear, actionable terms for a security analyst.
2. **Impact Analysis**: What is the potential impact if this is exploited? Include CIA triad assessment.
3. **CVSS Vector**: Suggest an appropriate CVSS 3.1 vector string.
4. **Remediation Steps**: Provide specific, actionable remediation steps.
5. **Risk Context**: How would this be used in a real attack scenario?

Respond in JSON format with keys: natural_description, impact_analysis, suggested_cvss_vector, remediation_steps (array), risk_context.
"""

SCAN_SUMMARY_PROMPT = """You are a senior penetration tester. Analyze the following scan results and produce a technically deep exploitation-oriented report. Be specific about endpoints, tools, and exploitation techniques.

TARGET: {target}
SCAN DURATION: {duration_seconds}s
WAF DETECTED: {waf_detected}

SEVERITY BREAKDOWN:
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}
- Total Findings: {total_findings}
- Total Endpoints: {total_endpoints}

SCANNER BREAKDOWN:
{findings_by_scanner}

ENDPOINT TYPES FOUND:
{endpoints_by_type}

FINDINGS DETAILED LIST:
{finding_lines}

Structure your response exactly as follows:

## Executive Summary
2-3 paragraph overview. MUST reference actual findings by name and severity and endpoint URLs. Do NOT say "no vulnerabilities" unless all severity counts are truly zero.

## Critical & High Findings
For each critical/high finding: endpoint URL, CVSS, exploit technique (e.g., "use curl to download .git/config at /foo"), real-world impact, recommended tooling (e.g., git-dumper, sqlmap, ffuf).

## Medium Findings
Summarize medium-severity findings. Recommend which should be prioritized and why.

## Attack Narrative
Step-by-step chain showing how an attacker could combine these findings into a full compromise. Be specific — reference exact endpoints and expected outcomes. Example: "1. Download .git repository via git-dumper → 2. Extract DB credentials from config → 3. Access admin panel at /admin → ..."

## Recommended Actions
Top 5 prioritized remediation steps. For each: what to fix, why, and how (specific config changes, code fixes, or WAF rules).

Respond in JSON format with keys: executive_summary, critical_findings, medium_findings, attack_narrative, recommended_actions.
"""

FINDING_ANALYSIS_PROMPT = """You are a senior penetration tester. Analyze this finding in detail.

FINDING:
Title: {title}
Description: {description}
Severity: {severity}
Scanner: {scanner_name}
Endpoint: {endpoint_url}
Evidence: {evidence_json}

Provide a technical analysis with:
1. **Technical Impact** — What exactly is the risk? Be specific about data/assets at risk.
2. **Exploitation Path** — Step-by-step commands/tools (e.g., curl, sqlmap, ffuf) to verify or exploit this.
3. **Remediation** — Specific code/config changes. Include code snippets or config file diffs.
4. **Chaining Potential** — Can this finding be combined with others for a larger attack?
5. **Analyst Confidence** — Low / Medium / High — and why.

Respond in JSON with keys: technical_impact, exploitation_path, remediation, chaining_potential, analyst_confidence.
"""


COMPREHENSIVE_SUMMARY_PROMPT = """You are a senior security architect. Produce a comprehensive executive analysis of this scan.

TARGET: {target}
FINDINGS COUNT: {total_findings}
SEVERITY BREAKDOWN:
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

FINDINGS:
{finding_lines}

Produce a structured report with:
1. **Executive Summary** — 2-3 paragraph overview for C-level/management audience.
2. **Critical & High Findings Deep-Dive** — For each critical/high finding: endpoint, CVSS (if available), exact risk, exploitation technique, tooling.
3. **Attack Narrative** — Step-by-step chain showing how findings combine into a full compromise path. Reference exact endpoints.
4. **Prioritized Remediation Roadmap** — Top 7 actions ordered by risk reduction. For each: what, why, how (code/config/WAF rule).
5. **Overall Risk Assessment** — One paragraph final verdict with risk level (Critical/High/Medium/Low).

Respond in JSON with keys: executive_summary, critical_deep_dive, attack_narrative, remediation_roadmap, risk_assessment.
"""


TRAINING_PAIR_PROMPT = """You are a cybersecurity training data generator. Create a high-quality training pair for fine-tuning a security analysis LLM.

CONTEXT:
Scan was performed against: {target}
Scanner that found this: {scanner_name}

FINDING:
Title: {title}
Severity: {severity}
Evidence: {evidence_json}

PROMPT: Generate a security analyst's analysis of this finding.
RESPONSE: Write a comprehensive analysis as if by a senior penetration tester.

Output in JSON format with keys: prompt (string), response (string).
"""


SCAN_STRATEGY_PROMPT = """You are a senior penetration test strategist. Given the target's technology profile, recommend an optimal scanning strategy.

TARGET: {target}
SERVER: {server}
FRAMEWORK: {framework} (confidence: {framework_confidence})
CMS: {cms}
SCRIPTING LANGUAGE: {scripting}
WAF: {waf}
COOKIES: {cookies}
EXPOSED PATHS: {exposed_paths}

Available scanners:
- crawler (depth 0-3, discovers pages)
- directory_scanner (brute-force paths)
- api_scanner (probes API endpoints)
- misconfig_scanner (headers, CORS, debug, ports)
- anomaly_detector (timing/status analysis)
- form_scanner (XSS probing, CSRF checks)

Recommend:
1. priority_scanners: list of scanner names to prioritize (rank by expected yield)
2. skip_scanners: list of scanners that are unlikely to find anything
3. augment_wordlists: object mapping scanner_name -> list of extra paths to probe
4. parameter_focus: list of attack vectors to emphasize (e.g. "LFI", "IDOR", "SSRF", "XSS", "SQLi")
5. optimal_crawl_depth: integer 0-3 (0=none, 3=deep)
6. enable_exploit_mode: boolean (aggressive payloads vs safe probes)
7. rationale: string explaining the strategy

Respond in JSON format with exactly these keys:
priority_scanners, skip_scanners, augment_wordlists, parameter_focus, optimal_crawl_depth, enable_exploit_mode, rationale
"""
