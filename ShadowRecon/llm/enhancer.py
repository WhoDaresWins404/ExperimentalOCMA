import asyncio
import json
from typing import Optional

from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider
from .prompts import FINDING_ANALYSIS_PROMPT, COMPREHENSIVE_SUMMARY_PROMPT, SCAN_STRATEGY_PROMPT, format_findings_for_summary
from core.config import ScanConfig
from core.models import Finding, ScanResult, LLMAnalysis, TechFingerprint, ScanStrategy
from core.exceptions import LLMUnavailable

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class LLMEnhancer:
    def __init__(self, config: ScanConfig):
        self.config = config.llm
        self._provider = None

    def _severity_threshold(self) -> int:
        return SEVERITY_ORDER.get(self.config.enrich_min_severity, 3)

    def _qualifies(self, finding: Finding) -> bool:
        return SEVERITY_ORDER.get(finding.severity.value, 0) >= self._severity_threshold()

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

        tasks = [enrich_one(f) for f in findings if self._qualifies(f)]
        tasks += [asyncio.ensure_future(asyncio.sleep(0, result=f)) for f in findings if not self._qualifies(f)]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                enriched.append(r)
            elif isinstance(r, Exception):
                pass
        return enriched

    async def analyze_finding(self, finding: Finding) -> dict:
        if not self.config.enabled:
            return {"error": "LLM is disabled"}
        try:
            provider = await self._get_provider()
        except LLMUnavailable as e:
            return {"error": str(e)}

        prompt = FINDING_ANALYSIS_PROMPT.format(
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            scanner_name=finding.scanner_name,
            endpoint_url=finding.endpoint_id or "N/A",
            evidence_json=json.dumps(finding.evidence, indent=2)[:3000],
        )

        try:
            response = await asyncio.wait_for(
                provider._request(prompt),
                timeout=120,
            )
            parsed = await provider._parse_json_response(response)
            analysis = {
                "technical_impact": parsed.get("technical_impact", ""),
                "exploitation_path": parsed.get("exploitation_path", ""),
                "remediation": parsed.get("remediation", ""),
                "chaining_potential": parsed.get("chaining_potential", ""),
                "analyst_confidence": parsed.get("analyst_confidence", ""),
            }

            finding.llm_analysis = LLMAnalysis(
                natural_description=analysis["technical_impact"],
                impact_analysis=analysis.get("chaining_potential", ""),
                remediation_steps=[analysis.get("remediation", "")],
                raw_response=response[:1000],
                model_used=f"{self.config.provider}/{self.config.model_name}",
                processing_time_ms=0,
            )
            finding.is_llm_enhanced = True
            if analysis.get("remediation"):
                finding.remediation = analysis["remediation"]

            return analysis
        except Exception as e:
            return {"error": str(e)}

    async def comprehensive_summary(self, findings: list[Finding], target: str) -> dict:
        if not self.config.enabled:
            return {"error": "LLM is disabled"}
        try:
            provider = await self._get_provider()
        except LLMUnavailable as e:
            return {"error": str(e)}

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        finding_lines = []
        for f in sorted(findings, key=lambda x: x.cvss_score or 0, reverse=True):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
            cvss = f"CVSS:{f.cvss_score:.1f}" if f.cvss_score else "CVSS:N/A"
            desc = (f.description or "")[:200].replace("\n", " ")
            finding_lines.append(f"  [{sev.upper()}] {f.title} ({cvss}, scanner: {f.scanner_name})")
            if desc:
                finding_lines.append(f"    {desc}")

        prompt = COMPREHENSIVE_SUMMARY_PROMPT.format(
            target=target,
            total_findings=len(findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            finding_lines="\n".join(finding_lines),
        )

        try:
            response = await asyncio.wait_for(
                provider._request(prompt),
                timeout=300,
            )
            parsed = await provider._parse_json_response(response)
            return {
                "executive_summary": parsed.get("executive_summary", ""),
                "critical_deep_dive": parsed.get("critical_deep_dive", ""),
                "attack_narrative": parsed.get("attack_narrative", ""),
                "remediation_roadmap": parsed.get("remediation_roadmap", ""),
                "risk_assessment": parsed.get("risk_assessment", ""),
            }
        except Exception as e:
            return {"error": str(e)}

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

        tasks = [generate_one(f) for f in findings if self._qualifies(f)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                pairs.append(r)
        return pairs

    async def generate_scan_strategy(self, fp: TechFingerprint, target: str) -> ScanStrategy:
        """Optional Phase 1 strategy — uses LLM to recommend scanner priorities."""
        if not self.config.enabled:
            return ScanStrategy(rationale="LLM disabled")

        try:
            provider = await self._get_provider()
        except LLMUnavailable:
            return ScanStrategy(rationale="LLM unavailable")

        prompt = SCAN_STRATEGY_PROMPT.format(
            target=target,
            server=fp.server or "unknown",
            framework=fp.framework or "unknown",
            framework_confidence=fp.framework_confidence,
            cms=fp.cms or "none",
            scripting=fp.scripting or "unknown",
            waf=fp.waf or "none",
            cookies=", ".join(fp.cookies),
            exposed_paths="\n".join(fp.exposed_paths) if fp.exposed_paths else "none",
        )

        try:
            response = await asyncio.wait_for(
                provider._request(prompt),
                timeout=self.config.strategize_timeout if hasattr(self.config, 'strategize_timeout') else 120,
            )
            parsed = await provider._parse_json_response(response)
            return ScanStrategy(
                priority_scanners=parsed.get("priority_scanners", []),
                skip_scanners=parsed.get("skip_scanners", []),
                augmented_wordlists=parsed.get("augment_wordlists", {}),
                parameter_focus=parsed.get("parameter_focus", []),
                optimal_crawl_depth=parsed.get("optimal_crawl_depth", 1),
                enable_exploit_mode=parsed.get("enable_exploit_mode", False),
                rationale=parsed.get("rationale", ""),
            )
        except Exception as e:
            return ScanStrategy(rationale=f"LLM strategy error: {e}")
