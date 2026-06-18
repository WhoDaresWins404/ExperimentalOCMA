import asyncio
import time
import json
from datetime import datetime
from typing import Optional, Callable, Any

from .config import ScanConfig
from .models import (
    ScanTarget, ScanResult, ScanSummary, ScanStatus,
    Endpoint, Finding, Campaign, ScanSession, GraphNode, GraphEdge,
    NodeType, EdgeType, FindingSeverity, CVSSVector
)
from .database import Database
from .session import CampaignManager, ScanSessionManager
from .deduplicator import Deduplicator
from scanners.registry import ScannerRegistry
from scanners.base import BaseScanner
from core.exceptions import ShadowReconError, WAFDetected, ScanCancelled


ProgressCallback = Callable[[str, Any], None]


class ScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.db = Database(config)
        self.campaign_mgr = CampaignManager(self.db)
        self.session_mgr = ScanSessionManager(self.db)
        self.deduplicator = Deduplicator()
        self._progress_callbacks: list[ProgressCallback] = []
        self._cancelled = False
        self._waf_state: dict = {}

    def on_progress(self, callback: ProgressCallback):
        self._progress_callbacks.append(callback)

    def _emit(self, event: str, data: Any):
        for cb in self._progress_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    asyncio.create_task(cb(event, data))
                else:
                    cb(event, data)
            except Exception:
                pass

    def cancel(self):
        self._cancelled = True

    async def initialize(self):
        await self.db.initialize()

    async def shutdown(self):
        await self.db.close()

    async def create_campaign(self, name: str, description: str = "", tags: list[str] = None) -> Campaign:
        return await self.campaign_mgr.create(name, description, tags)

    async def list_campaigns(self) -> list[Campaign]:
        return await self.campaign_mgr.list_all()

    async def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        return await self.campaign_mgr.get(campaign_id)

    async def run_scan(
        self,
        campaign_id: str,
        target: str,
        config_override: dict = None,
        session_id: str = None,
    ) -> ScanResult:
        self._cancelled = False
        merged = self.config.model_dump()
        if config_override:
            for key, value in config_override.items():
                if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                    merged[key].update(value)
                else:
                    merged[key] = value
        scan_config = ScanConfig(**merged)
        config_dict = merged

        if session_id:
            await self.session_mgr.update_status(session_id, ScanStatus.PENDING)
        else:
            session = await self.session_mgr.create(campaign_id, target, config_dict)
            session_id = session.id

        result = ScanResult(session_id=session_id, target=target, status=ScanStatus.PENDING)
        result.started_at = datetime.utcnow()
        start_time = time.time()

        try:
            await self.session_mgr.update_status(session_id, ScanStatus.WAF_CHECK)
            self._emit("status", {"session_id": session_id, "status": ScanStatus.WAF_CHECK.value})

            waf_findings, waf_endpoints = await self._run_waf_check(target, session_id, scan_config)

            await self.session_mgr.update_status(session_id, ScanStatus.SCANNING)
            self._emit("status", {"session_id": session_id, "status": ScanStatus.SCANNING.value})

            scan_target = ScanTarget(url=target)

            scanner_instances = ScannerRegistry.instantiate_all(
                scan_config, session_id, self._waf_state
            )

            if scan_config.scan_mode == "waf_only":
                scanner_instances.clear()
                scanner_results: dict = {}
            else:
                scanner_results = await self._run_scanners(
                    scan_target, scanner_instances, session_id, scan_config
                )
            scanner_instances.clear()

            await self.session_mgr.update_status(session_id, ScanStatus.DEDUP)
            self._emit("status", {"session_id": session_id, "status": ScanStatus.DEDUP.value})

            all_eps = waf_endpoints
            all_finds = waf_findings
            for finds, eps in scanner_results.values():
                all_eps.extend(eps)
                all_finds.extend(finds)

            scanner_results.clear()

            deduped_endpoints = await self.deduplicator.dedup_endpoints(all_eps)
            deduped_findings = await self.deduplicator.dedup_findings(all_finds)

            all_eps.clear()
            all_finds.clear()

            result.endpoints = deduped_endpoints
            for ep in deduped_endpoints:
                await self.db.add_endpoint(ep)
                self._emit("endpoint", ep.model_dump())

            llm_summary_text = ""
            if scan_config.llm.enabled and deduped_findings:
                await self.session_mgr.update_status(session_id, ScanStatus.LLM_ENRICH)
                self._emit("status", {"session_id": session_id, "status": ScanStatus.LLM_ENRICH.value})
                from llm.enhancer import LLMEnhancer
                enhancer = LLMEnhancer(scan_config)
                enriched = await enhancer.enrich_findings(deduped_findings, session_id)
                result.findings = enriched
                llm_summary_text = await enhancer.generate_summary(result)
                for finding in enriched:
                    self._emit("finding", finding.model_dump())
                    await self.db.add_finding(finding)
            else:
                for finding in deduped_findings:
                    self._emit("finding", finding.model_dump())
                    await self.db.add_finding(finding)
                result.findings = deduped_findings

            await self.session_mgr.update_status(session_id, ScanStatus.GENERATING_REPORT)
            self._emit("status", {"session_id": session_id, "status": ScanStatus.GENERATING_REPORT.value})

            await self.session_mgr.finalize(session_id, ScanStatus.COMPLETED)
            result.status = ScanStatus.COMPLETED
            result.ended_at = datetime.utcnow()
            duration = time.time() - start_time

            summary = self._build_summary(result, duration, llm_summary_text)
            result.stats = summary.model_dump()
            try:
                await self.session_mgr.update_stats(session_id, result.stats)
            except Exception:
                pass

            self._emit("complete", {
                "session_id": session_id,
                "summary": summary.model_dump(),
            })

        except ScanCancelled:
            result.status = ScanStatus.CANCELLED
            result.ended_at = datetime.utcnow()
            await self.session_mgr.finalize(session_id, ScanStatus.CANCELLED)
            self._emit("cancelled", {"session_id": session_id})

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print(f"[!] Scan engine error: {e}\n{tb}")
            result.status = ScanStatus.FAILED
            result.ended_at = datetime.utcnow()
            result.errors.append(f"{e}\n{tb}")
            await self.session_mgr.add_error(session_id, f"{e}\n{tb}")
            await self.session_mgr.finalize(session_id, ScanStatus.FAILED)
            self._emit("error", {"session_id": session_id, "error": str(e), "traceback": tb})

        return result

    async def _run_waf_check(self, target: str, session_id: str, scan_config: ScanConfig = None) -> tuple[list[Finding], list[Endpoint]]:
        from scanners.waf_detector import WAFDetector
        detector = WAFDetector(scan_config or self.config, session_id)
        scan_target = ScanTarget(url=target)
        findings, endpoints = await detector.scan(scan_target)
        if detector.detected_waf:
            self._waf_state["waf_name"] = detector.detected_waf["name"]
            self._waf_state["confidence"] = detector.detected_waf.get("confidence", 0)
            self._waf_state["evasion_headers"] = detector.get_evasion_headers()
            if (scan_config or self.config).evasion.auto_evasion:
                self._waf_state["active"] = True
        return findings, endpoints

    async def _run_scanners(
        self,
        target: ScanTarget,
        scanners: dict[str, BaseScanner],
        session_id: str,
        scan_config: ScanConfig = None,
    ) -> dict[str, tuple[list[Finding], list[Endpoint]]]:
        results = {}

        cfg = scan_config or self.config
        mode = cfg.scan_mode
        if mode == "light":
            scanner_order = ["crawler_scanner", "directory_scanner", "misconfig_scanner"]
        else:
            scanner_order = ["crawler_scanner", "api_scanner", "directory_scanner", "misconfig_scanner", "anomaly_detector", "form_scanner"]

        for name in scanner_order:
            if self._cancelled:
                raise ScanCancelled()
            if name not in scanners:
                continue
            scanner = scanners[name]
            try:
                self._emit("scanner_start", {"scanner": name, "session_id": session_id})
                findings, endpoints = await scanner.scan(target)
                results[name] = (findings, endpoints)
                self._emit("scanner_done", {
                    "scanner": name,
                    "findings": len(findings),
                    "endpoints": len(endpoints),
                    "session_id": session_id,
                })
            except Exception as e:
                self._emit("scanner_error", {"scanner": name, "error": str(e), "session_id": session_id})
                results[name] = ([], [])
            finally:
                await scanner.cleanup()

        return results

    def _build_summary(self, result: ScanResult, duration: float, llm_summary: str = "") -> ScanSummary:
        by_type = {}
        for ep in result.endpoints:
            t = ep.type.value if hasattr(ep.type, "value") else str(ep.type)
            by_type[t] = by_type.get(t, 0) + 1

        by_scanner = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "none": 0}
        for f in result.findings:
            by_scanner[f.scanner_name] = by_scanner.get(f.scanner_name, 0) + 1
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1

        top_risks = [
            f.title for f in sorted(
                result.findings,
                key=lambda x: x.cvss_score or 0,
                reverse=True,
            )[:5] if f.cvss_score and f.cvss_score >= 4.0
        ]

        return ScanSummary(
            session_id=result.session_id,
            total_endpoints=len(result.endpoints),
            total_findings=len(result.findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            scan_duration_seconds=round(duration, 2),
            endpoints_by_type=by_type,
            findings_by_scanner=by_scanner,
            top_risks=top_risks,
            llm_summary=llm_summary,
        )

    async def get_session_result(self, session_id: str) -> Optional[dict]:
        session = await self.session_mgr.get(session_id)
        if not session:
            return None
        endpoints = await self.db.get_session_endpoints(session_id)
        findings = await self.db.get_session_findings(session_id)
        nodes, edges = await self.db.get_session_graph(session_id)
        return {
            "session": session,
            "endpoints": endpoints,
            "findings": findings,
            "graph": {"nodes": nodes, "edges": edges},
        }
