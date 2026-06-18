from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget


class _FormExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict] = []
        self._current_form: dict = None

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, ad.get("action", "")) if ad.get("action") else self.base_url,
                "method": ad.get("method", "get").upper(),
                "inputs": [],
                "has_csrf": False,
            }
        elif tag == "input" and self._current_form is not None:
            inp = {"name": ad.get("name", ""), "type": ad.get("type", "text"), "value": ad.get("value", "")}
            self._current_form["inputs"].append(inp)
            name_lower = ad.get("name", "").lower()
            if any(t in name_lower for t in ("csrf", "token", "_token", "authenticity_token", "nonce")):
                self._current_form["has_csrf"] = True
        elif tag in ("textarea", "select") and self._current_form is not None:
            self._current_form["inputs"].append({"name": ad.get("name", ""), "type": tag, "value": ""})

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


XSS_PROBES = [
    "<test>",
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]


@register_scanner
class FormScanner(BaseScanner):
    name = "form_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []

        try:
            resp = await self.request("GET", target.url)
            ep = self.make_endpoint(url=target.url, status_code=resp.status_code,
                                    content_type=resp.headers.get("content-type", ""),
                                    discovered_by=self.name)
            endpoints.append(ep)

            ct = (resp.headers.get("content-type", "") or "").lower()
            if "text/html" not in ct:
                return findings, endpoints

            extractor = _FormExtractor(target.url)
            extractor.feed(resp.text)

            for form in extractor.forms:
                findings.extend(self._check_form_csrf(form))
                if self.config.xss_mode == "probe":
                    findings.extend(await self._probe_reflection(target.url, form))

        except Exception:
            pass

        return findings, endpoints

    def _check_form_csrf(self, form: dict) -> list:
        finds = []
        if not form.get("has_csrf", False):
            finds.append(self.make_finding(
                title="Missing CSRF Token on Form",
                description=f"Form targeting {form.get('action', '')} has no visible CSRF token.",
                severity="medium",
                evidence={"form_action": form.get("action", ""), "input_count": len(form.get("inputs", []))},
                confidence=0.7,
                tags=["csrf", "form"],
            ))
        return finds

    async def _probe_reflection(self, page_url: str, form: dict) -> list:
        finds = []
        inputs = [i for i in form.get("inputs", []) if i["type"] in ("text", "search", "textarea", "hidden", "")]

        for inp in inputs[:3]:
            name = inp.get("name", "")
            if not name:
                continue

            for probe in XSS_PROBES:
                try:
                    action = form.get("action", page_url)
                    method = form.get("method", "GET")

                    import urllib.parse
                    if method == "GET":
                        resp = await self.request("GET", f"{action}?{urllib.parse.urlencode({name: probe})}")
                    else:
                        resp = await self.request("POST", action, data={name: probe})

                    reflection = self._find_reflection(resp.text or "", probe)
                    if reflection:
                        finds.append(self.make_finding(
                            title="Reflected Input Detected in Form",
                            description=f"Form input '{name}' reflects user input in response. Possible XSS vector.",
                            severity="high" if not reflection.get("encoded") else "medium",
                            evidence={
                                "form_action": action, "input_name": name, "payload": probe,
                                "reflection_type": reflection["type"], "encoded": reflection.get("encoded", False),
                                "status_code": resp.status_code,
                            },
                            confidence=0.6 if reflection.get("encoded") else 0.9,
                            tags=["xss", "reflected_input", "form"],
                        ))
                        break
                except Exception:
                    continue
        return finds

    def _find_reflection(self, body: str, payload: str) -> dict | None:
        if not body or not payload:
            return None
        if payload in body:
            return {"type": "exact", "encoded": False}
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped in body:
            return {"type": "html_entity_encoded", "encoded": True}
        import html as html_mod
        for enc in (html_mod.escape(payload), payload.replace('"', "&quot;"), payload.replace("'", "&#x27;")):
            if enc in body:
                return {"type": "partially_encoded", "encoded": True}
        return None
