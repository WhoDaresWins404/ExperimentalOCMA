import json
import asyncio
import os
import httpx
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from core.config import ScanConfig
from core.engine import ScanEngine
from core.models import ScanStatus, ScanSummary, ScanSession
from scanners.registry import ScannerRegistry
from core.exceptions import LLMUnavailable
from mapping.mapper import Mapper
from reporting.report_generator import ReportGenerator
from exporters.training_data import TrainingDataExporter


class ScanRequest(BaseModel):
    url: str
    campaign_name: str = "default"
    campaign_description: str = ""
    threads: int = 25
    timeout: int = 30
    scan_mode: str = "full"
    detection_mode: str = "detect"
    enable_proxy: bool = False
    enable_llm: bool = False
    auth_type: str = "none"
    auth_cookie_string: str = ""
    auth_bearer_token: str = ""
    auth_header_key: str = ""
    auth_header_value: str = ""
    auth_basic_username: str = ""
    auth_basic_password: str = ""
    crawl_depth: int = 2
    xss_mode: str = "probe"
    enable_llm_payloads: bool = False
    enabled_scanners: list[str] = []


class CampaignCreate(BaseModel):
    name: str
    description: str = ""
    tags: list[str] = []


def create_app(config: ScanConfig = None) -> FastAPI:
    if config is None:
        config = ScanConfig()

    app = FastAPI(title="ShadowRecon API", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
    if os.path.isdir(frontend_dist):
        app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="frontend_assets")

    engine = ScanEngine(config)
    report_gen = ReportGenerator(config.output_dir)
    training_exporter = TrainingDataExporter()

    active_scans: dict[str, asyncio.Task] = {}
    websocket_clients: dict[str, list[WebSocket]] = {}

    @app.on_event("startup")
    async def startup():
        await engine.initialize()

    @app.on_event("shutdown")
    async def shutdown():
        for task in active_scans.values():
            task.cancel()
        await engine.shutdown()

    @app.get("/")
    async def root():
        if os.path.isdir(frontend_dist) and os.path.exists(os.path.join(frontend_dist, "index.html")):
            return FileResponse(os.path.join(frontend_dist, "index.html"))
        return JSONResponse({
            "message": "ShadowRecon API running.",
            "docs": "/docs",
            "api": {
                "health": "/api/health",
                "campaigns": "/api/campaigns",
                "start_scan": "POST /api/scan",
                "websocket": "WS /ws/scan/{session_id}",
            },
            "frontend": "Build with: cd web/frontend && npm install && npm run build",
        })

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "tool": "ShadowRecon", "version": "1.0.0"}

    @app.get("/api/llm/check")
    async def check_llm(provider: str = "ollama", host: str = "", model: str = ""):
        from llm.ollama_provider import OllamaProvider
        from llm.openai_provider import OpenAIProvider
        cfg = config.llm
        test_host = host or cfg.ollama_host
        test_model = model or cfg.model_name
        result = {"provider": provider, "host": test_host, "model": test_model, "reachable": False, "error": ""}
        try:
            if provider == "ollama":
                llm = OllamaProvider(cfg)
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(f"{test_host.rstrip('/')}/api/tags")
                    if resp.status_code == 200:
                        data = resp.json()
                        models = [m["name"] for m in data.get("models", [])]
                        result["reachable"] = True
                        result["models"] = models
                        model_lower = test_model.lower()
                        result["model_found"] = any(model_lower in m.lower() for m in models)
                        if not result["model_found"]:
                            result["error"] = f"Model '{test_model}' not found. Available: {', '.join(models) or 'none'}"
                    else:
                        result["error"] = f"HTTP {resp.status_code}"
            else:
                llm = OpenAIProvider(cfg)
                if llm.health_check():
                    result["reachable"] = True
                else:
                    result["error"] = "No API key configured"
        except Exception as e:
            result["error"] = str(e)
        return result

    @app.post("/api/campaigns")
    async def create_campaign(req: CampaignCreate):
        campaign = await engine.create_campaign(req.name, req.description, req.tags)
        return campaign.model_dump()

    @app.get("/api/campaigns")
    async def list_campaigns():
        campaigns = await engine.list_campaigns()
        return [c.model_dump() for c in campaigns]

    @app.get("/api/campaigns/{campaign_id}")
    async def get_campaign(campaign_id: str):
        campaign = await engine.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")
        result = campaign.model_dump()
        sessions = await engine.session_mgr.get_campaign_sessions(campaign_id)
        result["sessions"] = sessions
        return result

    @app.delete("/api/campaigns/{campaign_id}")
    async def delete_campaign(campaign_id: str):
        await engine.campaign_mgr.delete(campaign_id)
        return {"deleted": campaign_id}

    @app.post("/api/scan")
    async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
        config_override = {
            "threads": req.threads,
            "timeout": req.timeout,
            "scan_mode": req.scan_mode,
            "detection_mode": req.detection_mode,
            "proxy": {"enabled": req.enable_proxy},
            "llm": {"enabled": req.enable_llm, "payload_gen_enabled": req.enable_llm_payloads},
            "depth": req.crawl_depth,
            "xss_mode": req.xss_mode,
            "auth": {
                "enabled": req.auth_type != "none",
                "auth_type": req.auth_type,
                "cookie_string": req.auth_cookie_string,
                "bearer_token": req.auth_bearer_token,
                "header_key": req.auth_header_key,
                "header_value": req.auth_header_value,
                "basic_username": req.auth_basic_username,
                "basic_password": req.auth_basic_password,
            },
            "enabled_scanners": req.enabled_scanners,
        }

        campaign = await engine.campaign_mgr.create(
            req.campaign_name,
            req.campaign_description,
        )

        session = await engine.session_mgr.create(
            campaign.id, req.url, config_override
        )

        async def progress_callback(event: str, data: dict):
            if session.id in websocket_clients:
                message = json.dumps({"event": event, "data": data}, default=str)
                dead = []
                for ws in websocket_clients[session.id]:
                    try:
                        await ws.send_text(message)
                    except Exception:
                        dead.append(ws)
                for ws in dead:
                    websocket_clients[session.id].remove(ws)

        engine.on_progress(progress_callback)

        async def wrapped_scan():
            try:
                result = await engine.run_scan(
                    campaign.id, req.url, config_override, session_id=session.id
                )
                if result.status == ScanStatus.COMPLETED:
                    mapper = Mapper(session.id)
                    mapper.process_results(result.endpoints, result.findings, result.target)
                    for node in mapper.get_graph_nodes():
                        await engine.db.add_graph_node(node)
                    for edge in mapper.get_graph_edges():
                        await engine.db.add_graph_edge(edge)
                    summary = result.stats
                    if summary and summary.get("session_id"):
                        report_gen.generate_all(result, ScanSummary(**summary))

                        if config.llm.enabled:
                            from llm.enhancer import LLMEnhancer
                            enhancer = LLMEnhancer(config)
                            pairs = await enhancer.generate_training_pairs(result.findings)
                            if pairs:
                                training_exporter.export_jsonl(pairs, session.id)
                    result.endpoints.clear()
                    result.findings.clear()
                elif result.status == ScanStatus.FAILED:
                    for err in result.errors:
                        print(f"[!] Scan failed: {err}")
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                print(f"[!] Scan failed: {e}\n{tb}")
                await engine.session_mgr.add_error(session.id, f"{e}\n{tb}")
                await engine.session_mgr.finalize(session.id, ScanStatus.FAILED)
                if session.id in websocket_clients:
                    for ws in websocket_clients[session.id]:
                        try:
                            await ws.send_text(json.dumps({"event": "error", "data": {"error": str(e)}}))
                        except Exception:
                            pass

        background_tasks.add_task(wrapped_scan)
        return {"status": "started", "campaign_id": campaign.id, "session_id": session.id}

    @app.get("/api/scan/{session_id}/status")
    async def get_scan_status(session_id: str):
        session = await engine.session_mgr.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        return {"session_id": session_id, "status": session.get("status"), "error_log": json.loads(session.get("error_log", "[]"))}

    @app.get("/api/scan/{session_id}/results")
    async def get_scan_results(session_id: str):
        result = await engine.get_session_result(session_id)
        if not result:
            raise HTTPException(404, "Session not found")
        session = result.get("session", {})
        if isinstance(session.get("stats"), str):
            try:
                session["stats"] = json.loads(session["stats"])
            except Exception:
                session["stats"] = {}
        return result

    @app.get("/api/scan/{session_id}/report")
    async def get_report(session_id: str, format: str = Query("html", pattern="^(html|json)$")):
        session = await engine.session_mgr.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        report_path = f"{config.output_dir}/shadowrecon_report_{session_id[:12]}.{format}"
        return FileResponse(report_path, filename=f"shadowrecon_report_{session_id[:12]}.{format}")

    @app.get("/api/scan/{session_id}/map")
    async def get_scan_map(session_id: str):
        session = await engine.session_mgr.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        nodes, edges = await engine.db.get_session_graph(session_id)
        for node in nodes:
            if isinstance(node.get("extra_data"), str):
                try:
                    node["metadata"] = json.loads(node.pop("extra_data"))
                except (json.JSONDecodeError, TypeError):
                    node["metadata"] = {}
            else:
                node["metadata"] = node.pop("extra_data", {})
        for edge in edges:
            if isinstance(edge.get("extra_data"), str):
                try:
                    edge["metadata"] = json.loads(edge.pop("extra_data"))
                except (json.JSONDecodeError, TypeError):
                    edge["metadata"] = {}
            else:
                edge["metadata"] = edge.pop("extra_data", {})
        return {"nodes": nodes, "edges": edges}

    @app.post("/api/llm/analyze-finding/{session_id}/{finding_id}")
    async def analyze_finding(session_id: str, finding_id: str):
        findings = await engine.db.get_session_findings(session_id)
        finding_data = next((f for f in findings if f.get("id") == finding_id), None)
        if not finding_data:
            raise HTTPException(404, "Finding not found")
        from core.models import Finding, FindingSeverity
        finding = Finding(
            id=finding_data["id"],
            session_id=finding_data["session_id"],
            scanner_name=finding_data["scanner_name"],
            title=finding_data["title"],
            description=finding_data.get("description", ""),
            severity=FindingSeverity(finding_data.get("severity", "medium")),
            evidence=json.loads(finding_data.get("evidence", "{}")),
            endpoint_id=finding_data.get("endpoint_id"),
            cvss_score=finding_data.get("cvss_score"),
            remediation=finding_data.get("remediation", ""),
            confidence=finding_data.get("confidence", 1.0),
        )
        llm_config = config.llm.model_copy(deep=True)
        llm_config.enabled = True
        from llm.enhancer import LLMEnhancer
        enhancer = LLMEnhancer(config)
        enhancer.config = llm_config
        analysis = await enhancer.analyze_finding(finding)
        if "error" in analysis:
            return {"error": analysis["error"]}
        await engine.db.update_finding_llm(finding)
        return analysis

    @app.post("/api/llm/analyze-scan/{session_id}")
    async def analyze_scan(session_id: str):
        session = await engine.session_mgr.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        findings_data = await engine.db.get_session_findings(session_id)
        if not findings_data:
            return {"error": "No findings found"}
        from core.models import Finding, FindingSeverity
        findings = [
            Finding(
                id=fd["id"], session_id=fd["session_id"], scanner_name=fd["scanner_name"],
                title=fd["title"], description=fd.get("description", ""),
                severity=FindingSeverity(fd.get("severity", "medium")),
                evidence=json.loads(fd.get("evidence", "{}")),
                endpoint_id=fd.get("endpoint_id"), cvss_score=fd.get("cvss_score"),
                remediation=fd.get("remediation", ""), confidence=fd.get("confidence", 1.0),
            ) for fd in findings_data
        ]
        llm_config = config.llm.model_copy()
        llm_config.enabled = True
        from llm.enhancer import LLMEnhancer
        enhancer = LLMEnhancer(config)
        enhancer.config = llm_config
        target = session.get("target", "unknown")
        analysis = await enhancer.comprehensive_summary(findings, target)
        if "error" in analysis:
            return {"error": analysis["error"]}

        sections = []
        if analysis.get("executive_summary"):
            sections.append("## Executive Summary")
            sections.append(analysis["executive_summary"])
        if analysis.get("critical_deep_dive"):
            sections.append("\n## Critical & High Findings Deep-Dive")
            sections.append(analysis["critical_deep_dive"])
        if analysis.get("attack_narrative"):
            sections.append("\n## Attack Narrative")
            sections.append(analysis["attack_narrative"])
        if analysis.get("remediation_roadmap"):
            sections.append("\n## Remediation Roadmap")
            sections.append(analysis["remediation_roadmap"])
        if analysis.get("risk_assessment"):
            sections.append("\n## Risk Assessment")
            sections.append(analysis["risk_assessment"])
        summary_text = "\n\n".join(sections)

        stats = json.loads(session.get("stats", "{}"))
        stats["llm_summary"] = summary_text
        await engine.session_mgr.update_stats(session_id, stats)
        return {"summary": summary_text, "sections": analysis}

    @app.get("/api/scanners")
    async def list_scanners():
        manifests = ScannerRegistry.get_all_manifests()
        return sorted(
            [m.__dict__ for m in manifests.values()],
            key=lambda x: (x["category"], x["name"]),
        )

    @app.get("/api/export/training-data/{campaign_id}")
    async def export_training_data(campaign_id: str):
        campaign = await engine.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(404, "Campaign not found")
        sessions = await engine.session_mgr.get_campaign_sessions(campaign_id)
        all_pairs = []
        for sess in sessions:
            findings_data = await engine.db.get_session_findings(sess["id"])
            for fd in findings_data:
                from core.models import Finding, FindingSeverity, LLMAnalysis
                finding = Finding(
                    id=fd["id"],
                    session_id=fd["session_id"],
                    scanner_name=fd["scanner_name"],
                    title=fd["title"],
                    description=fd["description"],
                    severity=FindingSeverity(fd["severity"]) if fd.get("severity") else FindingSeverity.MEDIUM,
                    cvss_score=fd.get("cvss_score"),
                    evidence=json.loads(fd.get("evidence", "{}")),
                    is_llm_enhanced=fd.get("is_llm_enhanced", False),
                    remediation=fd.get("remediation", ""),
                    confidence=fd.get("confidence", 1.0),
                )
                all_pairs.append(training_exporter._finding_to_pair(finding, sess.get("target", "")))
        path = training_exporter.export_jsonl(all_pairs, campaign_id)
        return FileResponse(path, filename=f"training_data_{campaign_id}.jsonl")

    @app.websocket("/ws/scan/{session_id}")
    async def scan_websocket(websocket: WebSocket, session_id: str):
        await websocket.accept()
        if session_id not in websocket_clients:
            websocket_clients[session_id] = []
        websocket_clients[session_id].append(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            if session_id in websocket_clients:
                websocket_clients[session_id].remove(websocket)
                if not websocket_clients[session_id]:
                    del websocket_clients[session_id]

    @app.delete("/api/scan/{session_id}")
    async def delete_scan(session_id: str):
        await engine.db.delete_session(session_id)
        return {"status": "deleted", "session_id": session_id}

    return app


def run_server(config: ScanConfig = None, host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    app = create_app(config)
    uvicorn.run(app, host=host, port=port)
