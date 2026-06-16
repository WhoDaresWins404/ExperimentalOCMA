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

SCAN_SUMMARY_PROMPT = """You are a senior cybersecurity analyst. Summarize the following scan results for an executive audience.

SCAN RESULTS:
Target: {target}
Duration: {duration_seconds}s
Total Endpoints Found: {total_endpoints}
Total Findings: {total_findings}
Critical: {critical_count}
High: {high_count}
Medium: {medium_count}
Low: {low_count}

Top Risks:
{top_risks}

Please provide:
1. **Executive Summary**: 2-3 paragraph overview suitable for non-technical stakeholders.
2. **Critical Findings**: Highlight the most urgent issues requiring immediate attention.
3. **Attack Narrative**: Describe how a real attacker could chain these findings together.
4. **Recommended Actions**: Top 5 prioritized actions to remediate the findings.

Respond in JSON format with keys: executive_summary, critical_findings, attack_narrative, recommended_actions.
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
