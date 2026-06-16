import json
import time
from typing import Optional

import httpx

from .base import LLMProvider, LLMProviderError
from .prompts import FINDING_ENRICHMENT_PROMPT, SCAN_SUMMARY_PROMPT, TRAINING_PAIR_PROMPT
from core.config import LLMConfig
from core.models import Finding, LLMAnalysis, ScanResult


class OpenAIProvider(LLMProvider):
    def __init__(self, config: LLMConfig):
        self.config = config
        self.api_base = (config.api_base or "https://api.openai.com/v1").rstrip("/")
        self.api_key = config.api_key

    async def _request(self, prompt: str, system: str = "") -> str:
        url = f"{self.api_base}/chat/completions"
        payload = {
            "model": self.config.model_name or "gpt-4",
            "messages": [
                {"role": "system", "content": system or "You are a senior cybersecurity analyst."},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            raise LLMProviderError(f"OpenAI error: {str(e)}")

    async def _parse_json_response(self, text: str) -> dict:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    pass
            return {"raw_response": text}

    async def enrich_finding(self, finding: Finding) -> Optional[Finding]:
        start = time.perf_counter()
        prompt = FINDING_ENRICHMENT_PROMPT.format(
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            scanner_name=finding.scanner_name,
            endpoint_url=finding.endpoint_id or "N/A",
            evidence_json=json.dumps(finding.evidence, indent=2)[:2000],
        )
        try:
            response = await self._request(prompt)
            parsed = await self._parse_json_response(response)
            elapsed = int((time.perf_counter() - start) * 1000)
            finding.llm_analysis = LLMAnalysis(
                natural_description=parsed.get("natural_description", ""),
                impact_analysis=parsed.get("impact_analysis", ""),
                suggested_cvss_vector=parsed.get("suggested_cvss_vector", ""),
                remediation_steps=parsed.get("remediation_steps", []),
                raw_response=response[:1000],
                model_used=f"openai/{self.config.model_name}",
                processing_time_ms=elapsed,
            )
            finding.is_llm_enhanced = True
            if parsed.get("remediation_steps"):
                finding.remediation = "\n".join(parsed["remediation_steps"])
            return finding
        except LLMProviderError:
            return finding

    async def summarize_scan(self, result: ScanResult) -> str:
        summary = result.stats if hasattr(result, "stats") else {}
        prompt = SCAN_SUMMARY_PROMPT.format(
            target=result.target,
            duration_seconds=summary.get("scan_duration_seconds", 0),
            total_endpoints=summary.get("total_endpoints", 0),
            total_findings=summary.get("total_findings", 0),
            critical_count=summary.get("critical_count", 0),
            high_count=summary.get("high_count", 0),
            medium_count=summary.get("medium_count", 0),
            low_count=summary.get("low_count", 0),
            top_risks="\n".join(f"- {r}" for r in summary.get("top_risks", [])),
        )
        try:
            response = await self._request(prompt)
            parsed = await self._parse_json_response(response)
            return parsed.get("executive_summary", response[:1000])
        except LLMProviderError:
            return "LLM summary unavailable."

    async def generate_training_pair(self, finding: Finding) -> dict:
        prompt = TRAINING_PAIR_PROMPT.format(
            target=finding.endpoint_id or "unknown",
            scanner_name=finding.scanner_name,
            title=finding.title,
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            evidence_json=json.dumps(finding.evidence, indent=2)[:2000],
        )
        try:
            response = await self._request(prompt)
            parsed = await self._parse_json_response(response)
            return {
                "prompt": parsed.get("prompt", f"Analyze: {finding.title}"),
                "response": parsed.get("response", response[:1000]),
                "model": f"openai/{self.config.model_name}",
                "finding_type": finding.scanner_name,
                "severity": str(finding.severity),
            }
        except LLMProviderError:
            return {
                "prompt": f"Analyze security finding: {finding.title}",
                "response": f"Finding: {finding.title}\nDescription: {finding.description}",
                "model": "fallback",
                "finding_type": finding.scanner_name,
                "severity": str(finding.severity),
            }

    async def health_check(self) -> bool:
        return bool(self.api_key)
