import hashlib
import hmac
import json
from typing import Optional


class WebhookReceiver:
    def __init__(self, engine, hmac_secret: str = ""):
        self._engine = engine
        self._secret = hmac_secret

    async def handle(self, payload: dict, signature: Optional[str] = None) -> dict:
        if self._secret and signature:
            expected = hmac.new(
                self._secret.encode(), json.dumps(payload, sort_keys=True).encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, signature):
                return {"error": "Invalid signature", "accepted": False}

        url = payload.get("url", "")
        if not url:
            return {"error": "url is required", "accepted": False}

        campaign_name = payload.get("campaign_name", "webhook")
        config_override = {
            "threads": payload.get("threads", 25),
            "timeout": payload.get("timeout", 30),
            "scan_mode": payload.get("scan_mode", "full"),
            "enabled_scanners": payload.get("enabled_scanners", []),
        }

        campaign = await self._engine.campaign_mgr.create(campaign_name, f"Webhook-triggered scan: {url}")
        session = await self._engine.session_mgr.create(campaign.id, url, config_override)

        import asyncio
        asyncio.create_task(self._engine.run_scan(campaign.id, url, config_override, session_id=session.id))

        return {
            "accepted": True,
            "session_id": session.id,
            "campaign_id": campaign.id,
        }
