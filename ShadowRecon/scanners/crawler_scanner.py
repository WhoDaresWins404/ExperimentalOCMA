import re
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, EndpointType


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: set[str] = set()
        self.forms: list[dict] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a":
            href = attrs_dict.get("href", "").strip()
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                self.links.add(href)
        elif tag == "form":
            self.forms.append({
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").upper(),
            })
        elif tag == "iframe":
            src = attrs_dict.get("src", "").strip()
            if src:
                self.links.add(src)
        elif tag == "frame":
            src = attrs_dict.get("src", "").strip()
            if src:
                self.links.add(src)


@register_scanner
class CrawlerScanner(BaseScanner):
    name = "crawler_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        visited: set[str] = set()
        to_visit: list[tuple[str, int]] = [(target.url, 0)]
        base_domain = urlparse(target.url).netloc

        seen_paths: set[str] = set()

        while to_visit:
            url, depth = to_visit.pop(0)
            if url in visited:
                continue
            if depth > self.config.depth:
                continue
            if urlparse(url).netloc and urlparse(url).netloc != base_domain:
                continue

            visited.add(url)

            try:
                resp = await self.request("GET", url)
                ep = self.make_endpoint(
                    url=url,
                    method="GET",
                    type_hint="web_page",
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    response_body=resp.text,
                    discovered_by=self.name,
                )
                endpoints.append(ep)

                ct = (resp.headers.get("content-type", "") or "").lower()
                if "text/html" not in ct and "application/xhtml" not in ct:
                    continue

                extractor = _LinkExtractor()
                extractor.feed(resp.text)

                for href in extractor.links:
                    absolute = urljoin(url, href)
                    parsed = urlparse(absolute)
                    if parsed.netloc and parsed.netloc != base_domain:
                        continue
                    if parsed.scheme not in ("http", "https"):
                        continue
                    path = parsed.path.rstrip("/") or "/"
                    if path in seen_paths:
                        continue
                    seen_paths.add(path)
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                    if parsed.query:
                        clean_url += f"?{parsed.query}"
                    if clean_url not in visited:
                        to_visit.append((clean_url, depth + 1))

            except Exception as e:
                self._stats["errors"] += 1

        return findings, endpoints
