import json
import time
from typing import Optional

import httpx

from .base import LLMProvider, LLMProviderError
from .prompts import FINDING_ENRICHMENT_PROMPT, SCAN_SUMMARY_PROMPT, TRAINING_PAIR_PROMPT, format_findings_for_summary, format_llm_section
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
        print(f"[LLM] OpenAI call: model={self.config.model_name} prompt_len={len(prompt)} timeout={self.config.timeout}s")
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                t0 = time.time()
                resp = await client.post(url, json=payload, headers=headers)
                elapsed = time.time() - t0
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                print(f"[LLM] OpenAI OK: {elapsed:.1f}s response_len={len(content)}")
                return content
        except Exception as e:
            print(f"[LLM] OpenAI FAIL: {str(e)[:200]}")
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
                remediation_steps=self._coerce_str_list(parsed.get("remediation_steps", [])),
                raw_response=response[:1000],
                model_used=f"openai/{self.config.model_name}",
                processing_time_ms=elapsed,
            )
            finding.is_llm_enhanced = True
            steps = self._coerce_str_list(parsed.get("remediation_steps", []))
            if steps:
                finding.remediation = "\n".join(steps)
            return finding
        except LLMProviderError:
            return finding

    async def summarize_scan(self, result: ScanResult) -> str:
        summary = result.stats if hasattr(result, "stats") else {}
        ctx = format_findings_for_summary(result)
        prompt = SCAN_SUMMARY_PROMPT.format(
            target=result.target,
            duration_seconds=summary.get("scan_duration_seconds", 0),
            total_endpoints=summary.get("total_endpoints", 0),
            total_findings=summary.get("total_findings", 0),
            critical_count=summary.get("critical_count", 0),
            high_count=summary.get("high_count", 0),
            medium_count=summary.get("medium_count", 0),
            low_count=summary.get("low_count", 0),
            waf_detected=ctx["waf_detected"],
            findings_by_scanner=ctx["findings_by_scanner"],
            endpoints_by_type=ctx["endpoints_by_type"],
            finding_lines=ctx["finding_lines"],
        )
        try:
            response = await self._request(prompt)
            parsed = await self._parse_json_response(response)

            sections = {
                "executive_summary": format_llm_section(parsed.get("executive_summary", "")),
                "critical_findings": format_llm_section(parsed.get("critical_findings", "")),
                "medium_findings": format_llm_section(parsed.get("medium_findings", "")),
                "attack_narrative": format_llm_section(parsed.get("attack_narrative", "")),
                "recommended_actions": format_llm_section(parsed.get("recommended_actions", "")),
            }

            parts = []
            if sections["executive_summary"]:
                parts.append("## Executive Summary")
                parts.append(sections["executive_summary"])
            if sections["critical_findings"]:
                parts.append("\n## Critical & High Findings")
                parts.append(sections["critical_findings"])
            if sections["medium_findings"]:
                parts.append("\n## Medium Findings")
                parts.append(sections["medium_findings"])
            if sections["attack_narrative"]:
                parts.append("\n## Attack Narrative")
                parts.append(sections["attack_narrative"])
            if sections["recommended_actions"]:
                parts.append("\n## Recommended Actions")
                parts.append(sections["recommended_actions"])

            return "\n\n".join(parts) if parts else response[:1000]
        except LLMProviderError:
            return ""

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

    async def generate_payload(self, prompt: str, timeout: int = 120) -> str:
        url = f"{self.api_base}/chat/completions"
        payload = {
            "model": self.config.model_name or "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a senior XSS engineer. Return only the raw payload."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.4,
            "max_tokens": 500,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        print(f"[LLM] OpenAI payload_gen: model={self.config.model_name} timeout={timeout}s")
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                t0 = time.time()
                resp = await client.post(url, json=payload, headers=headers)
                elapsed = time.time() - t0
                resp.raise_for_status()
                text = resp.json()["choices"][0]["message"]["content"].strip()
                print(f"[LLM] OpenAI payload_gen OK: {elapsed:.1f}s payload_len={len(text)}")
                return text
        except Exception as e:
            print(f"[LLM] OpenAI payload_gen FAIL: {str(e)[:200]}")
            return ""
