import json
import logging
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import httpx
import yaml
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


@dataclass
class NotificationEvent:
    event_type: str
    title: str
    description: str
    severity: Optional[str] = None
    target: Optional[str] = None
    scanner: Optional[str] = None
    finding_id: Optional[str] = None
    session_id: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class ProviderConfig:
    enabled: bool = True
    type: str = ""
    webhook_url: str = ""
    channel: str = ""
    bot_token: str = ""
    chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    rate_limit_seconds: int = 60
    min_severity: str = "low"
    events: list[str] = field(default_factory=lambda: ["scan.complete", "finding.critical", "scan.failed", "scan.started", "scan.aborted", "scan.cancelled"])


class NotificationManager:
    def __init__(self, config_path: str = ""):
        self._providers: list[ProviderConfig] = []
        self._last_sent: dict[str, datetime] = {}
        self._env = Environment(loader=FileSystemLoader(
            str(Path(__file__).parent.parent / "templates" / "notifications")
        ))
        if config_path:
            self.load_config(config_path)

    def load_config(self, path: str):
        raw = yaml.safe_load(Path(path).read_text())
        for entry in raw.get("providers", []):
            self._providers.append(ProviderConfig(**entry))

    def add_provider(self, cfg: ProviderConfig):
        self._providers.append(cfg)

    async def send(self, event: NotificationEvent):
        for provider in self._providers:
            if not provider.enabled:
                continue
            if event.event_type not in provider.events:
                continue
            sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if sev_rank.get(event.severity or "info", 0) < sev_rank.get(provider.min_severity, 1):
                continue
            last = self._last_sent.get(provider.webhook_url or provider.type)
            if last and (datetime.utcnow() - last).total_seconds() < provider.rate_limit_seconds:
                continue
            try:
                await self._dispatch(provider, event)
                self._last_sent[provider.webhook_url or provider.type] = datetime.utcnow()
            except Exception as e:
                logger.warning("Notification failed for %s: %s", provider.type, e)

    async def _dispatch(self, p: ProviderConfig, event: NotificationEvent):
        if p.type == "discord":
            await self._discord(p, event)
        elif p.type == "slack":
            await self._slack(p, event)
        elif p.type == "telegram":
            await self._telegram(p, event)
        elif p.type == "smtp":
            await self._smtp(p, event)
        elif p.type == "webhook":
            await self._custom_webhook(p, event)

    def _render(self, template_name: str, event: NotificationEvent) -> str:
        tpl = self._env.get_template(template_name)
        return tpl.render(event=event)

    async def _discord(self, p: ProviderConfig, event: NotificationEvent):
        color_map = {"critical": 15548997, "high": 15105570, "medium": 16776960, "low": 3447003}
        payload = {
            "embeds": [{
                "title": event.title,
                "description": event.description,
                "color": color_map.get(event.severity or "low", 3447003),
                "fields": [
                    {"name": "Severity", "value": event.severity or "N/A", "inline": True},
                    {"name": "Target", "value": event.target or "N/A", "inline": True},
                    {"name": "Scanner", "value": event.scanner or "N/A", "inline": True},
                ],
                "timestamp": datetime.utcnow().isoformat(),
            }]
        }
        if p.webhook_url:
            async with httpx.AsyncClient() as client:
                await client.post(p.webhook_url, json=payload)

    async def _slack(self, p: ProviderConfig, event: NotificationEvent):
        payload = {
            "text": f"[{event.severity.upper()}] {event.title}",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": event.title}},
                {"type": "section", "text": {"type": "mrkdwn", "text": event.description}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{event.severity or 'N/A'}"},
                    {"type": "mrkdwn", "text": f"*Target:*\n{event.target or 'N/A'}"},
                ]},
            ]
        }
        if p.webhook_url:
            async with httpx.AsyncClient() as client:
                await client.post(p.webhook_url, json=payload)

    async def _telegram(self, p: ProviderConfig, event: NotificationEvent):
        text = (
            f"*[{event.severity.upper()}] {event.title}*\n"
            f"{event.description}\n"
            f"Target: {event.target or 'N/A'}"
        )
        if p.bot_token and p.chat_id:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"https://api.telegram.org/bot{p.bot_token}/sendMessage",
                    json={"chat_id": p.chat_id, "text": text, "parse_mode": "Markdown"},
                )

    async def _smtp(self, p: ProviderConfig, event: NotificationEvent):
        if not all([p.smtp_host, p.from_addr, p.to_addrs]):
            return
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{event.severity}] {event.title}" if event.severity else event.title
        msg["From"] = p.from_addr
        msg["To"] = ", ".join(p.to_addrs)
        html = self._render("smtp.html", event)
        msg.attach(MIMEText(html, "html"))
        import smtplib
        with smtplib.SMTP(p.smtp_host, p.smtp_port) as server:
            if p.smtp_user and p.smtp_pass:
                server.starttls()
                server.login(p.smtp_user, p.smtp_pass)
            server.sendmail(p.from_addr, p.to_addrs, msg.as_string())

    async def send_scan_event(self, event_type: str, session_id: str, target: str, campaign_id: str = "",
                                description: str = "", extra: dict = None):
        await self.send(NotificationEvent(
            event_type=event_type,
            title=f"Scan {event_type.split('.')[-1]}: {target}",
            description=description or f"Scan session {session_id} on {target} has {event_type.split('.')[-1]}",
            target=target,
            session_id=session_id,
            extra=extra or {},
        ))

    async def _custom_webhook(self, p: ProviderConfig, event: NotificationEvent):
        secret = p.bot_token or ""
        payload = json.dumps({
            "event": event.event_type,
            "title": event.title,
            "description": event.description,
            "severity": event.severity,
            "target": event.target,
            "scanner": event.scanner,
            "finding_id": event.finding_id,
            "session_id": event.session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "extra": event.extra,
        }, default=str)
        headers = {"Content-Type": "application/json"}
        if secret:
            signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            headers["X-Signature-256"] = signature
        async with httpx.AsyncClient() as client:
            await client.post(p.webhook_url, content=payload, headers=headers)
