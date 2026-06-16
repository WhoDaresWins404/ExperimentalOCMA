import asyncio
from typing import Optional

from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider
from core.config import ScanConfig
from core.models import Finding, ScanResult
from core.exceptions import LLMUnavailable


class LLMEnhancer:
    def __init__(self, config: ScanConfig):
        self.config = config.llm
        self._provider = None

    async def _get_provider(self):
        if self._provider is not None:
            return self._provider
        if not self.config.enabled:
            raise LLMUnavailable("LLM is disabled in config")
        if self.config.provider == "ollama":
            self._provider = OllamaProvider(self.config)
        else:
            self._provider = OpenAIProvider(self.config)
        if not await self._provider.health_check():
            raise LLMUnavailable(f"LLM provider '{self.config.provider}' unreachable at {self.config.ollama_host}")
        return self._provider

    async def enrich_findings(self, findings: list[Finding], session_id: str) -> list[Finding]:
        if not self.config.enabled or not self.config.enrich_findings:
            return findings
        try:
            provider = await self._get_provider()
        except LLMUnavailable:
            return findings

        semaphore = asyncio.Semaphore(3)
        enriched = []

        async def enrich_one(finding: Finding) -> Finding:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        provider.enrich_finding(finding),
                        timeout=self.config.timeout,
                    )
                except Exception:
                    return finding

        tasks = [enrich_one(f) for f in findings if f.severity.value in ("high", "critical", "medium")]
        tasks += [asyncio.ensure_future(asyncio.sleep(0, result=f)) for f in findings if f not in tasks]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                enriched.append(r)
            elif isinstance(r, Exception):
                pass
        return enriched

    async def generate_summary(self, result: ScanResult) -> str:
        if not self.config.enabled or not self.config.generate_summary:
            return ""
        try:
            provider = await self._get_provider()
            return await provider.summarize_scan(result)
        except (LLMUnavailable, Exception):
            return ""

    async def generate_training_pairs(self, findings: list[Finding]) -> list[dict]:
        if not self.config.enabled or not self.config.generate_training_data:
            return []
        try:
            provider = await self._get_provider()
        except LLMUnavailable:
            return []

        semaphore = asyncio.Semaphore(3)
        pairs = []

        async def generate_one(finding: Finding) -> Optional[dict]:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        provider.generate_training_pair(finding),
                        timeout=self.config.timeout,
                    )
                except Exception:
                    return None

        tasks = [generate_one(f) for f in findings if f.severity.value in ("high", "critical", "medium")]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                pairs.append(r)
        return pairs
