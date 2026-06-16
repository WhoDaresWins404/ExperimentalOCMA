import json
import asyncio
import os
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
from mapping.mapper import Mapper
from reporting.report_generator import ReportGenerator
from exporters.training_data import TrainingDataExporter


class ScanRequest(BaseModel):
    url: str
    campaign_name: str = "default"
    campaign_description: str = ""
    threads: int = 25
    timeout: int = 30
    detection_mode: str = "detect"
    enable_proxy: bool = False
    enable_llm: bool = False


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

    @app.post("/api/scan")
    async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
        config_override = {
            "threads": req.threads,
            "timeout": req.timeout,
            "detection_mode": req.detection_mode,
            "proxy": {"enabled": req.enable_proxy},
            "llm": {"enabled": req.enable_llm},
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
                mapper = Mapper(session.id)
                mapper.process_results(result.endpoints, result.findings, result.target)
                summary = result.stats
                report_gen.generate_all(result, ScanSummary(**summary) if isinstance(summary, dict) else summary)

                if config.llm.enabled:
                    from llm.enhancer import LLMEnhancer
                    enhancer = LLMEnhancer(config)
                    pairs = await enhancer.generate_training_pairs(result.findings)
                    if pairs:
                        training_exporter.export_jsonl(pairs, session.id)
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
        return {"nodes": nodes, "edges": edges}

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
