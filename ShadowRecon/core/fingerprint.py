import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from .models import TechFingerprint
from .config import ScanConfig


FRAMEWORK_SIGNATURES = {
    "wordpress": {
        "cookies": {"wordpress_", "wp-settings-", "wp-settings-time-"},
        "paths": {"/wp-json/", "/wp-content/", "/wp-includes/"},
        "headers": {},
        "body_patterns": [r"/wp-content/themes/", r"WordPress", r"<meta name=\"generator\" content=\"WordPress"],
    },
    "laravel": {
        "cookies": {"laravel_session", "xsrf-token", "XSRF-TOKEN"},
        "paths": {"/.env", "/_ignition/health-check"},
        "headers": {},
        "body_patterns": [r"Laravel", r"livewire"],
    },
    "django": {
        "cookies": {"csrftoken", "sessionid"},
        "paths": {"/admin/", "/api/"},
        "headers": {},
        "body_patterns": [r"django", r"csrfmiddlewaretoken"],
    },
    "express": {
        "cookies": {"connect.sid"},
        "paths": {},
        "headers": {"x-powered-by": "express"},
        "body_patterns": [],
    },
    "rails": {
        "cookies": {"_session_id"},
        "paths": {"/rails/info"},
        "headers": {"x-powered-by": "phusion passenger"},
        "body_patterns": [r"csrf-param"],
    },
    "aspnet": {
        "cookies": {".aspnet", "__requestverificationtoken"},
        "paths": {},
        "headers": {"x-powered-by": "asp.net"},
        "body_patterns": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
    },
}

SERVER_LANGUAGE_MAP = {
    "nginx": ("nginx", None),
    "apache": ("apache", "php"),
    "iis": ("iis", "asp.net"),
    "caddy": ("caddy", None),
    "cloudflare": (None, None),
    "php": (None, "php"),
    "python": (None, "python"),
    "gunicorn": (None, "python"),
    "node": (None, "node"),
    "express": ("express", "node"),
}

LANGUAGE_HINTS = {
    ".php": "php",
    ".asp": "asp.net",
    ".aspx": "asp.net",
    ".jsp": "java",
    ".do": "java",
    ".py": "python",
    ".rb": "ruby",
}


class FingerprintEngine:
    """Phase 0 reconnaissance — detect tech stack with minimal requests."""

    def __init__(self, config: ScanConfig, client: Optional[httpx.AsyncClient] = None):
        self.config = config
        self._client = client

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout),
                follow_redirects=True,
                verify=False,
            )
        return self._client

    async def cleanup(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def fingerprint(self, target_url: str, waf_state: dict = None) -> TechFingerprint:
        """Fingerprint a target URL with a few strategic requests."""
        fp = TechFingerprint()
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        if waf_state and waf_state.get("waf_name"):
            fp.waf = waf_state["waf_name"]

        client = await self._get_client()

        # Request 1: main page
        try:
            resp = await client.get(target_url, timeout=10)
            self._analyze_response(resp, fp)
        except Exception:
            pass

        # Request 2: robots.txt
        try:
            robots = await client.get(f"{base}/robots.txt", timeout=5)
            if robots.status_code == 200:
                for line in robots.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[-1].strip()
                        if path:
                            fp.exposed_paths.append(f"robots.txt: {path}")
        except Exception:
            pass

        # Request 3: common framework paths (HEAD for speed)
        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            for path in sig["paths"]:
                if fp.framework:
                    break
                try:
                    h_resp = await client.head(f"{base}{path}", timeout=5)
                    if h_resp.status_code < 500:
                        fp.framework = fw_name
                        fp.framework_confidence = 0.8
                        break
                except Exception:
                    continue

        # Fallback: body pattern re-check
        if not fp.framework:
            for fw_name, sig in FRAMEWORK_SIGNATURES.items():
                if fp.framework:
                    break
                for pat in sig["body_patterns"]:
                    if getattr(fp.headers, "body", None) and re.search(pat, fp.headers["body"], re.IGNORECASE):
                        fp.framework = fw_name
                        fp.framework_confidence = 0.7
                        break

        # Scripting language from URL path extension hints
        if not fp.scripting:
            for ext, lang in LANGUAGE_HINTS.items():
                if ext in target_url:
                    fp.scripting = lang
                    break

        return fp

    def _analyze_response(self, resp: httpx.Response, fp: TechFingerprint):
        # Server header
        server = resp.headers.get("server", "").lower()
        if server:
            fp.server = server
            for key, (svr, lang) in SERVER_LANGUAGE_MAP.items():
                if key in server:
                    if svr and not fp.framework:
                        fp.framework_confidence = max(fp.framework_confidence, 0.5)
                    if lang and not fp.scripting:
                        fp.scripting = lang
                    break

        # X-Powered-By
        powered = resp.headers.get("x-powered-by", "").lower()
        if powered:
            fp.headers["x-powered-by"] = powered
            if "express" in powered:
                fp.framework = "express"
                fp.framework_confidence = 0.8
            elif "asp.net" in powered:
                fp.framework = "aspnet"
                fp.framework_confidence = 0.8
            elif "php" in powered and not fp.scripting:
                fp.scripting = "php"

        # Generator meta
        generator = resp.headers.get("x-generator", "") or resp.headers.get("generator", "")
        if generator:
            g = generator.lower()
            if "wordpress" in g:
                fp.framework = "wordpress"
                fp.framework_confidence = 0.9

        # Cookies
        for cookie in resp.cookies:
            name = cookie.name.lower()
            fp.cookies.append(name)
            for fw_name, sig in FRAMEWORK_SIGNATURES.items():
                for cname in sig["cookies"]:
                    if cname.lower() == name or name.startswith(cname.lower()):
                        fp.framework = fw_name
                        fp.framework_confidence = max(fp.framework_confidence, 0.75)
                        break

        # Store body for later pattern matching
        if hasattr(resp, "text") and resp.text:
            fp.headers["body"] = resp.text[:5000]
