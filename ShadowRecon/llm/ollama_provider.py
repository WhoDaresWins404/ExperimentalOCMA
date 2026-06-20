import json
import time
from typing import Optional

import httpx

from .base import LLMProvider, LLMProviderError
from .prompts import FINDING_ENRICHMENT_PROMPT, SCAN_SUMMARY_PROMPT, TRAINING_PAIR_PROMPT, format_findings_for_summary, format_llm_section
from core.config import LLMConfig
from core.models import Finding, LLMAnalysis, ScanResult


class OllamaProvider(LLMProvider):
    def __init__(self, config: LLMConfig):
        self.config = config
        self.base_url = config.ollama_host.rstrip("/")
        self.model = config.model_name
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.config.timeout, limits=httpx.Limits(max_keepalive_connections=5, max_connections=10))
        return self._client

    async def cleanup(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(self, prompt: str, system: str = "", timeout: int = None) -> str:
        effective_timeout = timeout if timeout is not None else self.config.timeout
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        print(f"[LLM] Ollama call: model={self.model} prompt_len={len(prompt)} timeout={effective_timeout}s")
        try:
            client = await self._get_client()
            t0 = time.time()
            resp = await client.post(url, json=payload, timeout=effective_timeout)
            elapsed = time.time() - t0
            resp.raise_for_status()
            data = resp.json()
            print(f"[LLM] Ollama OK: {elapsed:.1f}s response_len={len(data.get('response', ''))}")
            return data.get("response", "")
        except httpx.HTTPStatusError as e:
            print(f"[LLM] Ollama FAIL: HTTP {e.response.status_code}")
            raise LLMProviderError(f"Ollama HTTP error: {e.response.status_code} - {e.response.text[:200]}")
        except httpx.TimeoutException:
            print(f"[LLM] Ollama FAIL: timeout after {effective_timeout}s")
            raise LLMProviderError(f"Ollama timeout after {effective_timeout}s")
        except Exception as e:
            print(f"[LLM] Ollama FAIL: {str(e)[:200]}")
            raise LLMProviderError(f"Ollama error: {str(e)}")

    async def _parse_json_response(self, text: str) -> dict:
        text = text.strip()
        # Strip markdown code fences wherever they appear
        if "```" in text:
            parts = text.split("```")
            for i, part in enumerate(parts):
                candidate = part.strip()
                if candidate.startswith("json"):
                    candidate = candidate[4:].strip()
                if candidate.startswith("{") and candidate.endswith("}"):
                    text = candidate
                    break
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
                model_used=f"ollama/{self.model}",
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
                "prompt": parsed.get("prompt",
                    f"Analyze the following security finding: {finding.title} on {finding.endpoint_id}"),
                "response": parsed.get("response", response[:1000]),
                "model": f"ollama/{self.model}",
                "finding_type": finding.scanner_name,
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
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
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def generate_payload(self, prompt: str, timeout: int = 120) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": "You are a senior XSS engineer. Return only the raw payload.",
            "temperature": 0.4,
            "max_tokens": 500,
            "stream": False,
        }
        print(f"[LLM] Ollama payload_gen: model={self.model} timeout={timeout}s")
        try:
            client = await self._get_client()
            t0 = time.time()
            resp = await client.post(url, json=payload, timeout=timeout)
            elapsed = time.time() - t0
            resp.raise_for_status()
            data = resp.json()
            text = (data.get("response", "") or "").strip()
            print(f"[LLM] Ollama payload_gen OK: {elapsed:.1f}s payload_len={len(text)}")
            return text
        except Exception as e:
            print(f"[LLM] Ollama payload_gen FAIL: {str(e)[:200]}")
            return ""
