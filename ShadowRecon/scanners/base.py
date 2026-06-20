import asyncio
import random
import time
import hashlib
from abc import ABC, abstractmethod
from typing import Optional
from urllib.parse import urlparse

import httpx
from httpx import AsyncClient, Limits, Timeout

from core.config import ScanConfig
from core.models import Finding, Endpoint, ScanTarget
from core.exceptions import WAFDetected, RateLimited, TargetUnreachable


class ProxyRotator:
    def __init__(self, config: ScanConfig):
        self.config = config.proxy
        self._index = 0

    def current(self) -> Optional[str]:
        if not self.config.enabled or not self.config.chain:
            return None
        if self.config.rotation == "round_robin":
            proxy = self.config.chain[self._index % len(self.config.chain)]
            self._index += 1
        else:
            proxy = random.choice(self.config.chain)
        return proxy

    def mounts(self) -> dict:
        if not self.config.enabled:
            return {}
        proxy = self.current()
        if not proxy:
            return {}
        transport = httpx.AsyncHTTPTransport(proxy=proxy)
        return {
            "http://": transport,
            "https://": transport,
        }


class BaseScanner(ABC):
    def __init__(
        self,
        config: ScanConfig,
        session_id: str,
        waf_state: dict = None,
        directive_bus=None,
    ):
        self.config = config
        self.session_id = session_id
        self.waf_state = waf_state or {}
        self.directive_bus = directive_bus
        self._results: list[Finding] = []
        self._endpoints: list[Endpoint] = []
        self._stats: dict = {"requests": 0, "errors": 0, "timeouts": 0}
        self._client: Optional[AsyncClient] = None
        self._augmented_paths: list[str] = []
        self._captured_ids: list[str] = []
        self._on_exchange: Optional[callable] = None

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        pass

    async def get_client(self) -> AsyncClient:
        if self._client is None:
            rotator = ProxyRotator(self.config)
            headers = {"Accept": "*/*"}
            if self.config.evasion.user_agent_rotation:
                headers["User-Agent"] = random.choice(self.config.evasion.user_agents)
            auth = self.config.auth
            if auth.enabled and auth.auth_type != "none":
                if auth.auth_type == "cookie" and auth.cookie_string:
                    headers["Cookie"] = auth.cookie_string
                elif auth.auth_type == "bearer" and auth.bearer_token:
                    headers["Authorization"] = f"Bearer {auth.bearer_token}"
                elif auth.auth_type == "header" and auth.header_key:
                    headers[auth.header_key] = auth.header_value
                elif auth.auth_type == "basic" and auth.basic_username:
                    import base64
                    raw = f"{auth.basic_username}:{auth.basic_password}"
                    headers["Authorization"] = f"Basic {base64.b64encode(raw.encode()).decode()}"
            try:
                limits = Limits(
                    max_connections=self.config.threads,
                    max_keepalive_connections=20,
                    max_response_size=self.config.max_response_size,
                )
            except TypeError:
                limits = Limits(
                    max_connections=self.config.threads,
                    max_keepalive_connections=20,
                )
            self._client = AsyncClient(
                mounts=rotator.mounts(),
                headers=headers,
                timeout=Timeout(self.config.timeout),
                limits=limits,
                follow_redirects=self.config.follow_redirects,
            )
        return self._client

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        client = await self.get_client()
        if self.config.evasion.jitter:
            delay = random.uniform(
                self.config.evasion.request_delay_min,
                self.config.evasion.request_delay_max,
            )
            await asyncio.sleep(delay)

        if self.waf_state.get("evasion_headers"):
            headers = kwargs.get("headers", {})
            headers.update(self.waf_state["evasion_headers"])
            kwargs["headers"] = headers

        for attempt in range(3):
            try:
                t0 = time.monotonic()
                resp = await client.request(method, url, **kwargs)
                elapsed = int((time.monotonic() - t0) * 1000)
                self._stats["requests"] += 1
                if self._on_exchange:
                    exchange_id = await self._on_exchange(
                        scanner_name=self.name,
                        url=url,
                        method=method,
                        status_code=resp.status_code,
                        request_headers=dict(kwargs.get("headers", {})),
                        request_body=kwargs.get("content", ""),
                        response_headers=dict(resp.headers),
                        response_body=resp.text or "",
                        timing_ms=elapsed,
                    )
                    if exchange_id:
                        self._captured_ids.append(exchange_id)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "60"))
                    raise RateLimited(retry_after=retry_after)
                return resp
            except httpx.TimeoutException:
                self._stats["timeouts"] += 1
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise
            except httpx.ConnectError as e:
                self._stats["errors"] += 1
                raise TargetUnreachable(url, str(e))
            except RateLimited:
                if attempt < 2:
                    await asyncio.sleep(retry_after)
                else:
                    raise

    def make_finding(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        endpoint: Endpoint = None,
        evidence: dict = None,
        confidence: float = 1.0,
        tags: list[str] = None,
    ) -> Finding:
        return Finding(
            session_id=self.session_id,
            endpoint_id=endpoint.id if endpoint else None,
            scanner_name=self.name,
            title=title,
            description=description,
            severity=severity,
            evidence=evidence or {},
            confidence=confidence,
            tags=tags or [],
        )

    def make_endpoint(
        self, url: str, method: str = "GET", type_hint: str = "unknown",
        status_code: int = None, content_type: str = None,
        response_body: str = None, discovered_by: str = "",
        metadata: dict = None,
    ) -> Endpoint:
        response_hash = None
        if response_body:
            response_hash = hashlib.sha256(response_body.encode()).hexdigest()[:16]
        return Endpoint(
            session_id=self.session_id,
            url=url,
            method=method,
            type=type_hint,
            status_code=status_code,
            content_type=content_type,
            response_hash=response_hash,
            response_size=len(response_body) if response_body else None,
            metadata=metadata or {},
            discovered_by=discovered_by or self.name,
            source="",
        )

    @property
    def effective_wordlist(self) -> list[str]:
        """Base wordlist merged with intelligence-driven augmented paths."""
        base = list(getattr(self, 'wordlist', []))
        if self._augmented_paths:
            seen = set(base)
            for p in self._augmented_paths:
                if p not in seen:
                    base.append(p)
                    seen.add(p)
        return base

    async def cleanup(self):
        self._results.clear()
        self._endpoints.clear()
        if self._client:
            await self._client.aclose()
            self._client = None

    @staticmethod
    def is_valid_url(url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
