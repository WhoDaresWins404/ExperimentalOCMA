import asyncio
import json
from typing import Optional

import httpx

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


COMMON_WS_PATHS = [
    "/ws", "/socket", "/websocket", "/sockjs", "/socket.io",
    "/api/ws", "/stream", "/realtime", "/events", "/live",
]


@register_scanner(manifest=ScannerManifest(
    name="websocket_scanner",
    category="discovery",
    risk_level="safe",
    estimated_cost=20,
    produces_tag_patterns=["websocket", "realtime"],
))
class WebSocketScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "websocket_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        up = self._ws_upgrade_url(target.url)
        parsed = httpx.URL(target.url)
        base = f"{parsed.scheme}://{parsed.host}"
        if parsed.port:
            base = f"{parsed.scheme}://{parsed.host}:{parsed.port}"

        for path in COMMON_WS_PATHS:
            ws_url = f"{up}{path}"
            try:
                resp = await self.request(
                    "GET", f"{base}{path}",
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    },
                )
                if resp.status_code == 101 or resp.headers.get("Upgrade", "").lower() == "websocket":
                    findings.append(self.make_finding(
                        title="WebSocket Endpoint Discovered",
                        description=f"WebSocket endpoint at {ws_url} accepted upgrade request.",
                        severity="info",
                        endpoint=self.make_endpoint(ws_url, discovered_by=self.name),
                        evidence={"path": path, "status": resp.status_code,
                                  "upgrade": resp.headers.get("Upgrade", "")},
                        confidence=0.9,
                        tags=["websocket"],
                    ))
                elif resp.status_code == 426:
                    findings.append(self.make_finding(
                        title="WebSocket Endpoint — Requires Upgrade",
                        description=f"Server at {ws_url} returned 426, indicating WebSocket support.",
                        severity="info",
                        endpoint=self.make_endpoint(ws_url, status_code=426, discovered_by=self.name),
                        evidence={"path": path},
                        confidence=0.7,
                        tags=["websocket"],
                    ))
            except Exception:
                pass

        return findings, endpoints

    @staticmethod
    def _ws_upgrade_url(http_url: str) -> str:
        return http_url.replace("https://", "wss://").replace("http://", "ws://")
