import asyncio
import time
import json
import uuid
from datetime import datetime
from typing import Optional, Callable, Any

from .config import ScanConfig
from .models import (
    ScanTarget, ScanResult, ScanSummary, ScanStatus,
    Endpoint, Finding, Campaign, ScanSession, GraphNode, GraphEdge,
    NodeType, EdgeType, FindingSeverity, CVSSVector,
    TechFingerprint, ScanStrategy,
)
from .database import Database
from .session import CampaignManager, ScanSessionManager
from .deduplicator import Deduplicator
from .directive import DirectiveBus
from .budget import TimeBudgetManager
from .intelligence import IntelligenceCore
from .scheduler import PriorityScheduler, ScanScheduler
from .fingerprint import FingerprintEngine
from scanners.registry import ScannerRegistry
from scanners.base import BaseScanner
from core.exceptions import ShadowReconError, WAFDetected, ScanCancelled, HostUnreachable
from core.host_monitor import HostMonitor
from core.callback_server import SSRFCallbackServer
from core.notifications import NotificationManager, NotificationEvent
from core.scope import load_scope_from_dict, ScopeConfig
from core.response_diff import ResponseDiffEngine


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
        self._cancel_reason: str = "user_requested"
        self._waf_state: dict = {}
        self._callback_server = SSRFCallbackServer()
        self._notifier = NotificationManager()
        self._response_diff = ResponseDiffEngine()
        self._scheduler = ScanScheduler(self)

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

    def cancel(self, reason: str = "user_requested"):
        self._cancelled = True
        self._cancel_reason = reason

    def _make_exchange_callback(self, session_id: str):
        async def _on_exchange(
            scanner_name: str, url: str, method: str, status_code: int,
            request_headers: dict, request_body: str,
            response_headers: dict, response_body: str, timing_ms: int,
        ) -> str:
            exchange_id = uuid.uuid4().hex[:12]
            body_preview = (response_body or "")[:500]
            ws_data = {
                "id": exchange_id,
                "url": url,
                "method": method,
                "status_code": status_code,
                "response_size": len(response_body or ""),
                "timing_ms": timing_ms,
                "scanner": scanner_name,
                "body_preview": body_preview,
            }
            self._emit("http_exchange", ws_data)
            asyncio.create_task(self.db.add_raw_response({
                "id": exchange_id,
                "session_id": session_id,
                "url": url,
                "method": method,
                "request_headers": json.dumps(request_headers),
                "request_body": request_body[:5000] if request_body else None,
                "response_headers": json.dumps(response_headers),
                "response_body": response_body[:5000] if response_body else None,
                "status_code": status_code,
                "timing_ms": timing_ms,
                "created_at": datetime.utcnow().isoformat(),
            }))
            return exchange_id
        return _on_exchange

    async def initialize(self):
        await self.db.initialize()
        import os
        notif_path = os.environ.get(
            "SHADOWRECON_NOTIFICATIONS",
            os.path.join(os.path.dirname(self.config.data_dir) if self.config.data_dir else ".", "notifications.yml"),
        )
        if os.path.exists(notif_path):
            self._notifier.load_config(notif_path)
        await self._scheduler.start()

    async def shutdown(self):
        await self._scheduler.stop()
        await self._callback_server.stop()
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
        self._cancel_reason = "user_requested"
        resume_state = None
        merged = self.config.model_dump()
        if config_override:
            resume_state = config_override.pop("_resume_state", None)
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

        # Scope validation
        scope_data = config_dict.get("scope", {})
        if scope_data:
            scope_cfg = load_scope_from_dict(scope_data)
            warning = scope_cfg.validate_target(target)
            if warning and "out of scope" in warning:
                raise ShadowReconError(warning)

        # Start SSRF callback server
        await self._callback_server.start()

        result = ScanResult(session_id=session_id, target=target, status=ScanStatus.PENDING)
        result.started_at = datetime.utcnow()
        start_time = time.time()

        try:
            # ── Phase 0: WAF Check ────────────────────────────────────────
            await self.session_mgr.update_status(session_id, ScanStatus.WAF_CHECK)
            self._emit("status", {"session_id": session_id, "status": ScanStatus.WAF_CHECK.value})

            waf_findings, waf_endpoints = await self._run_waf_check(target, session_id, scan_config)

            async def _scan_core():
                scan_target = ScanTarget(url=target)

                use_intel = scan_config.intelligence.enabled

                if use_intel:
                    # ── Phase 1a: RECONNAISSANCE ──────────────────────────
                    await self.session_mgr.update_status(session_id, ScanStatus.RECONNAISSANCE)
                    self._emit("status", {"session_id": session_id, "status": ScanStatus.RECONNAISSANCE.value})

                    fingerprinter = FingerprintEngine(scan_config)
                    tech_fp = await fingerprinter.fingerprint(target, self._waf_state)

                    # ── Phase 1b: STRATEGIZE ──────────────────────────────
                    await self.session_mgr.update_status(session_id, ScanStatus.STRATEGIZE)
                    self._emit("status", {"session_id": session_id, "status": ScanStatus.STRATEGIZE.value})

                    directive_bus = DirectiveBus()
                    budget_mgr = TimeBudgetManager(scan_config.max_scan_time)
                    budget_mgr.start()

                    intel = IntelligenceCore(directive_bus, scan_config)
                    await intel.set_profile(tech_fp)

                    # Optional LLM strategy
                    if scan_config.llm.enabled and scan_config.llm.strategize:
                        try:
                            from llm.enhancer import LLMEnhancer
                            enhancer = LLMEnhancer(scan_config)
                            llm_strategy = await enhancer.generate_scan_strategy(tech_fp, target)
                            await intel.apply_strategy(llm_strategy)
                        except Exception as e:
                            print(f"[!] LLM strategy failed (falling back to rules): {e}")

                    # ── Phase 2: ADAPTIVE_SCAN ────────────────────────────
                    await self.session_mgr.update_status(session_id, ScanStatus.ADAPTIVE_SCAN)
                    self._emit("status", {"session_id": session_id, "status": ScanStatus.ADAPTIVE_SCAN.value})

                    instances = ScannerRegistry.instantiate_all(
                        scan_config, session_id, self._waf_state, directive_bus
                    )
                    cb = self._make_exchange_callback(session_id)
                    for inst in instances.values():
                        inst._on_exchange = cb
                    if scan_config.enabled_scanners:
                        instances = {k: v for k, v in instances.items() if k in scan_config.enabled_scanners}
                    if resume_state:
                        completed = set(resume_state.get("completed_scanners", []))
                        if completed:
                            instances = {k: v for k, v in instances.items() if k not in completed}
                    scanner_instances = instances

                    if scan_config.scan_mode == "waf_only":
                        all_findings = waf_findings[:]
                        all_endpoints = waf_endpoints[:]
                    else:
                        host_monitor = HostMonitor(
                            target, scan_config.host_unreachable_timeout
                        )
                        await host_monitor.probe()

                        scheduler = PriorityScheduler(
                            scanner_instances, budget_mgr, directive_bus,
                            scan_config, host_monitor,
                        )
                        scheduler.build_from_profile(intel.profile, scan_config.scan_mode)

                        all_findings = waf_findings[:]
                        all_endpoints = waf_endpoints[:]

                        while True:
                            if self._cancelled:
                                for ep in all_endpoints:
                                    await self.db.add_endpoint(ep)
                                for f in all_findings:
                                    await self.db.add_finding(f)
                                await self._update_scanner_state(
                                    session_id, scheduler
                                )
                                raise ScanCancelled()
                            if host_monitor.is_dead:
                                raise HostUnreachable(target, host_monitor.unreachable_for)
                            await host_monitor.probe_if_needed()
                            job_result = await scheduler.run_next(scan_target)
                            if job_result is None:
                                break
                            scanner_name, (findings, endpoints) = job_result
                            for f in findings:
                                await intel.absorb_finding(f, scanner_name)
                            for ep in endpoints:
                                await intel.absorb_endpoint(ep, scanner_name)
                            all_findings.extend(findings)
                            all_endpoints.extend(endpoints)

                        await self._update_scanner_state(
                            session_id, scheduler
                        )
                    scanner_instances.clear()

                else:
                    # ── Legacy linear path (intelligence disabled) ───────
                    await self.session_mgr.update_status(session_id, ScanStatus.SCANNING)
                    self._emit("status", {"session_id": session_id, "status": ScanStatus.SCANNING.value})

                    instances = ScannerRegistry.instantiate_all(
                        scan_config, session_id, self._waf_state
                    )
                    cb = self._make_exchange_callback(session_id)
                    for inst in instances.values():
                        inst._on_exchange = cb
                    if scan_config.enabled_scanners:
                        instances = {k: v for k, v in instances.items() if k in scan_config.enabled_scanners}
                    if resume_state:
                        completed = set(resume_state.get("completed_scanners", []))
                        if completed:
                            instances = {k: v for k, v in instances.items() if k not in completed}
                    scanner_instances = instances

                    if scan_config.scan_mode == "waf_only":
                        scanner_instances.clear()
                        scanner_results = {}
                    else:
                        host_monitor = HostMonitor(
                            target, scan_config.host_unreachable_timeout
                        )
                        await host_monitor.probe()
                        scanner_results = await self._run_scanners_legacy(
                            scan_target, scanner_instances, session_id,
                            scan_config, host_monitor
                        )
                    scanner_instances.clear()

                    all_eps = waf_endpoints[:]
                    all_finds = waf_findings[:]
                    for finds, eps in scanner_results.values():
                        all_eps.extend(eps)
                        all_finds.extend(finds)
                    scanner_results.clear()

                    all_endpoints = all_eps
                    all_findings = all_finds

                # ── Phase 3: DEDUP ────────────────────────────────────────
                await self.session_mgr.update_status(session_id, ScanStatus.DEDUP)
                self._emit("status", {"session_id": session_id, "status": ScanStatus.DEDUP.value})

                deduped_endpoints = await self.deduplicator.dedup_endpoints(all_endpoints)
                deduped_findings = await self.deduplicator.dedup_findings(all_findings)

                result.endpoints = deduped_endpoints
                for ep in deduped_endpoints:
                    await self.db.add_endpoint(ep)
                    self._emit("endpoint", ep.model_dump())

                # ── Phase 4: LLM_ENRICH (unchanged) ──────────────────────
                if scan_config.llm.enabled and deduped_findings:
                    await self.session_mgr.update_status(session_id, ScanStatus.LLM_ENRICH)
                    self._emit("status", {"session_id": session_id, "status": ScanStatus.LLM_ENRICH.value})
                    from llm.enhancer import LLMEnhancer
                    enhancer = LLMEnhancer(scan_config)
                    enriched = await enhancer.enrich_findings(deduped_findings, session_id)
                    result.findings = enriched
                    for finding in enriched:
                        self._emit("finding", finding.model_dump())
                        await self.db.add_finding(finding)
                else:
                    for finding in deduped_findings:
                        self._emit("finding", finding.model_dump())
                        await self.db.add_finding(finding)
                    result.findings = deduped_findings

                # ── Phase 5: REPORT ───────────────────────────────────────
                await self.session_mgr.update_status(session_id, ScanStatus.GENERATING_REPORT)
                self._emit("status", {"session_id": session_id, "status": ScanStatus.GENERATING_REPORT.value})

                await self.session_mgr.finalize(session_id, ScanStatus.COMPLETED)
                result.status = ScanStatus.COMPLETED
                result.ended_at = datetime.utcnow()
                duration = time.time() - start_time

                summary = self._build_summary(result, duration, "")
                result.stats = summary.model_dump()
                try:
                    await self.session_mgr.update_stats(session_id, result.stats)
                except Exception:
                    pass

                self._emit("complete", {
                    "session_id": session_id,
                    "summary": summary.model_dump(),
                })

            await asyncio.wait_for(_scan_core(), timeout=scan_config.max_scan_time)

        except asyncio.TimeoutError:
            msg = f"Scan timed out after {scan_config.max_scan_time}s"
            print(f"[!] {msg}")
            result.status = ScanStatus.FAILED
            result.ended_at = datetime.utcnow()
            result.errors.append(msg)
            await self.session_mgr.add_error(session_id, msg)
            await self.session_mgr.finalize(session_id, ScanStatus.FAILED)
            self._emit("error", {"session_id": session_id, "error": msg})

        except ScanCancelled:
            result.status = ScanStatus.CANCELLED
            result.ended_at = datetime.utcnow()
            await self.session_mgr.finalize(session_id, ScanStatus.CANCELLED)
            self._emit("cancelled", {
                "session_id": session_id,
                "reason": self._cancel_reason or "user_requested",
            })

        except HostUnreachable as e:
            msg = str(e)
            print(f"[!] {msg}")
            result.status = ScanStatus.FAILED
            result.ended_at = datetime.utcnow()
            result.errors.append(msg)
            await self.session_mgr.add_error(session_id, msg)
            await self.session_mgr.finalize(session_id, ScanStatus.FAILED)
            self._emit("error", {"session_id": session_id, "error": msg})

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

        finally:
            await self._callback_server.stop()
            severity = "info"
            if result.status == ScanStatus.FAILED:
                severity = "high"
            elif result.status == ScanStatus.CANCELLED:
                severity = "medium"
            elif result.status == ScanStatus.COMPLETED:
                severity = "low"
            await self._notifier.send(NotificationEvent(
                event_type="scan.complete",
                title=f"Scan {result.status.value}: {target}",
                description=f"Session {session_id} completed with status {result.status.value}",
                severity=severity,
                target=target,
                session_id=session_id,
            ))

        return result

    async def _update_scanner_state(self, session_id: str, scheduler):
        """Persist completed scanner names, avoiding property descriptor issues."""
        completed = list(scheduler._completed) if scheduler else []
        await self.session_mgr.update_scanner_state(
            session_id, {"completed_scanners": completed}
        )

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

    async def _run_scanners_legacy(
        self,
        target: ScanTarget,
        scanners: dict[str, BaseScanner],
        session_id: str,
        scan_config: ScanConfig = None,
        host_monitor: HostMonitor = None,
    ) -> dict[str, tuple[list[Finding], list[Endpoint]]]:
        """Legacy linear scanner pipeline — used when intelligence is disabled."""
        results = {}
        completed_scanners = []

        cfg = scan_config or self.config
        mode = cfg.scan_mode
        if mode == "light":
            scanner_order = ["crawler_scanner", "directory_scanner", "misconfig_scanner"]
        else:
            scanner_order = ["crawler_scanner", "api_scanner", "directory_scanner",
                             "misconfig_scanner", "anomaly_detector", "form_scanner"]
        for name in scanners:
            if name not in scanner_order:
                scanner_order.append(name)

        for name in scanner_order:
            if self._cancelled:
                await self.session_mgr.update_scanner_state(
                    session_id, {"completed_scanners": completed_scanners}
                )
                raise ScanCancelled()
            if host_monitor and host_monitor.is_dead:
                raise HostUnreachable(target.url, host_monitor.unreachable_for)
            if host_monitor:
                await host_monitor.probe_if_needed()
            if name not in scanners:
                continue
            scanner = scanners[name]
            try:
                self._emit("scanner_start", {"scanner": name, "session_id": session_id})
                findings, endpoints = await scanner.scan(target)
                results[name] = (findings, endpoints)
                completed_scanners.append(name)
                await self.session_mgr.update_scanner_state(
                    session_id, {"completed_scanners": completed_scanners}
                )
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
