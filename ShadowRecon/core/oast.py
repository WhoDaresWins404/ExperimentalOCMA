import asyncio
import json
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OAST_SERVICES = {
    "interactsh": {
        "register_url": "https://oast.fun/register",
        "poll_url": "https://oast.fun/poll?id={session_id}",
        "domain": "{session_id}.oast.fun",
    },
    "interactsh_pro": {
        "register_url": "https://oast.pro/register",
        "poll_url": "https://oast.pro/poll?id={session_id}",
        "domain": "{session_id}.oast.pro",
    },
}


@dataclass
class OastInteraction:
    timestamp: str
    interaction_type: str  # dns, http, smtp
    remote_address: str
    raw_request: str
    protocol: str


@dataclass
class OastSession:
    service: str
    session_id: str
    domain: str
    poll_url: str
    interactions: list[OastInteraction] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


class OastManager:
    def __init__(self, service: str = "interactsh"):
        self._sessions: dict[str, OastSession] = {}
        self._service_config = OAST_SERVICES.get(service, OAST_SERVICES["interactsh"])
        self._polling_tasks: dict[str, asyncio.Task] = {}
        self._active = False

    async def create_session(self, campaign_id: str = "") -> OastSession:
        session_id = secrets.token_hex(16)
        domain = self._service_config["domain"].format(session_id=session_id)
        poll_url = self._service_config["poll_url"].format(session_id=session_id)
        register_url = self._service_config["register_url"]

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(register_url, json={"public-key": session_id})
                if resp.status_code not in (200, 201):
                    logger.warning("OAST registration failed: %s", resp.status_code)
        except Exception as e:
            logger.warning("OAST registration error: %s", e)

        session = OastSession(
            service=self._service_config["domain"],
            session_id=session_id,
            domain=domain,
            poll_url=poll_url,
        )
        self._sessions[session_id] = session
        return session

    def get_callback_url(self, session: OastSession, path: str = "") -> str:
        return f"http://{session.domain}/{path.lstrip('/')}"

    def get_callback_domain(self, session: OastSession) -> str:
        return session.domain

    async def start_polling(self, session_id: str, interval: int = 5):
        session = self._sessions.get(session_id)
        if not session:
            return
        if session_id in self._polling_tasks:
            return

        async def _poll():
            while session_id in self._sessions:
                try:
                    await self._poll_once(session)
                except Exception as e:
                    logger.debug("OAST poll error: %s", e)
                await asyncio.sleep(interval)

        self._polling_tasks[session_id] = asyncio.create_task(_poll())

    async def stop_polling(self, session_id: str):
        task = self._polling_tasks.pop(session_id, None)
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _poll_once(self, session: OastSession):
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(session.poll_url)
            if resp.status_code != 200:
                return
            data = resp.json()
            interactions = data.get("data", [])
            for item in interactions:
                interaction = OastInteraction(
                    timestamp=item.get("timestamp", ""),
                    interaction_type=item.get("type", "http"),
                    remote_address=item.get("remote-address", ""),
                    raw_request=item.get("raw-request", ""),
                    protocol=item.get("protocol", ""),
                )
                if interaction.raw_request not in {i.raw_request for i in session.interactions}:
                    session.interactions.append(interaction)

    def get_interactions(self, session_id: str) -> list[OastInteraction]:
        session = self._sessions.get(session_id)
        return list(session.interactions) if session else []

    def has_callback(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        return bool(session and session.interactions)

    async def cleanup(self):
        for sid in list(self._polling_tasks.keys()):
            await self.stop_polling(sid)
        self._sessions.clear()
