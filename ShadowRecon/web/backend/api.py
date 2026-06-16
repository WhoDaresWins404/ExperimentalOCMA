import json
import asyncio
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from core.config import ScanConfig
from core.engine import ScanEngine
from core.models import ScanStatus, ScanSummary
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

        async def progress_callback(event: str, data: dict):
            session_id = data.get("session_id", "")
            if session_id in websocket_clients:
                message = json.dumps({"event": event, "data": data}, default=str)
                dead = []
                for ws in websocket_clients[session_id]:
                    try:
                        await ws.send_text(message)
                    except Exception:
                        dead.append(ws)
                for ws in dead:
                    websocket_clients[session_id].remove(ws)

        engine.on_progress(progress_callback)

        task = asyncio.create_task(engine.run_scan(campaign.id, req.url, config_override))
        session_id = None

        async def wrapped_scan():
            nonlocal session_id
            try:
                result = await task
                session_id = result.session_id
                mapper = Mapper(session_id)
                mapper.process_results(result.endpoints, result.findings, result.target)
                graph = mapper.get_graph_json()

                summary = result.stats
                report_paths = report_gen.generate_all(result, ScanSummary(**summary) if isinstance(summary, dict) else summary)

                if config.llm.enabled:
                    from llm.enhancer import LLMEnhancer
                    enhancer = LLMEnhancer(config)
                    llm_summary = await enhancer.generate_summary(result)
                    if llm_summary:
                        summary["llm_summary"] = llm_summary
                    pairs = await enhancer.generate_training_pairs(result.findings)
                    if pairs:
                        training_path = training_exporter.export_jsonl(pairs, session_id)
                return result
            except Exception as e:
                pass

        background_tasks.add_task(wrapped_scan)
        return {"status": "started", "campaign_id": campaign.id}

    @app.get("/api/scan/{session_id}/status")
    async def get_scan_status(session_id: str):
        session = await engine.session_mgr.get(session_id)
        if not session:
            raise HTTPException(404, "Session not found")
        return {"session_id": session_id, "status": session.get("status")}

    @app.get("/api/scan/{session_id}/results")
    async def get_scan_results(session_id: str):
        result = await engine.get_session_result(session_id)
        if not result:
            raise HTTPException(404, "Session not found")
        return result

    @app.get("/api/scan/{session_id}/report")
    async def get_report(session_id: str, format: str = Query("html", regex="^(html|json)$")):
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
