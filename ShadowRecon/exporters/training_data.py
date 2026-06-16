import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import Finding, ScanResult


class TrainingDataExporter:
    def __init__(self, output_dir: str = "./training_data"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def export_jsonl(self, pairs: list[dict], session_id: str = "") -> str:
        path = os.path.join(self.output_dir, f"training_data_{session_id[:12] if session_id else datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for pair in pairs:
                f.write(json.dumps(pair, ensure_ascii=False) + "\n")
        return path

    def findings_to_pairs(self, findings: list[Finding], target: str = "") -> list[dict]:
        pairs = []
        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            if sev == "none":
                continue
            pair = self._finding_to_pair(finding, target)
            pairs.append(pair)
        return pairs

    def _finding_to_pair(self, finding: Finding, target: str = "") -> dict:
        prompt = (
            f"Analyze the following security finding discovered during a penetration test of {target or 'a web application'}.\n\n"
            f"Scanner: {finding.scanner_name}\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Severity: {finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)}\n"
            f"Endpoint: {finding.endpoint_id or 'N/A'}\n"
            f"CVSS Score: {finding.cvss_score or 'N/A'}\n"
            f"Confidence: {finding.confidence:.0%}\n\n"
            f"Provide a comprehensive analysis including: vulnerability description, impact assessment, "
            f"exploitation scenario, CVSS vector justification, and remediation steps."
        )
        response_parts = [f"## Finding: {finding.title}"]
        if finding.llm_analysis:
            analysis = finding.llm_analysis
            if analysis.natural_description:
                response_parts.append(f"\n### Description\n{analysis.natural_description}")
            if analysis.impact_analysis:
                response_parts.append(f"\n### Impact\n{analysis.impact_analysis}")
            if analysis.remediation_steps:
                response_parts.append(f"\n### Remediation\n" + "\n".join(f"- {s}" for s in analysis.remediation_steps))
        else:
            response_parts.append(f"\n### Description\n{finding.description}")
            response_parts.append(f"\n### Evidence\n```json\n{json.dumps(finding.evidence, indent=2)[:1000]}\n```")
            if finding.remediation:
                response_parts.append(f"\n### Remediation\n{finding.remediation}")

        return {
            "prompt": prompt,
            "response": "\n".join(response_parts),
            "metadata": {
                "source": "ShadowRecon",
                "scanner": finding.scanner_name,
                "severity": sev if not hasattr(finding.severity, 'value') else finding.severity.value,
                "cvss_score": finding.cvss_score,
                "finding_type": finding.title,
                "has_llm_analysis": finding.is_llm_enhanced,
                "model": finding.llm_analysis.model_used if finding.llm_analysis else "rule-based",
            },
        }
