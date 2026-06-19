from collections import deque
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, EndpointType, ScannerManifest


SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js",
                   ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz",
                   ".mp4", ".mp3", ".webm", ".avi", ".mov"}


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: set[str] = set()

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        if tag == "a":
            href = ad.get("href", "").strip()
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                self.links.add(href)
        elif tag in ("iframe", "frame"):
            src = ad.get("src", "").strip()
            if src:
                self.links.add(src)


@register_scanner(manifest=ScannerManifest(
    name="crawler_scanner",
    category="recon",
    risk_level="safe",
    estimated_cost=70,
    produces_endpoint_types=["WEB_PAGE", "STATIC_ASSET"],
    produces_tag_patterns=["crawl", "link"],
))
class CrawlerScanner(BaseScanner):
    name = "crawler_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        visited: set[str] = set()
        to_visit: deque[tuple[str, int]] = deque()
        to_visit.append((target.url, 0))
        base_domain = urlparse(target.url).netloc
        seen_normalized: set[str] = set()
        page_count = 0
        max_pages = self.config.max_crawl_pages

        while to_visit and page_count < max_pages:
            url, depth = to_visit.popleft()
            if url in visited:
                continue
            if depth > self.config.depth:
                continue
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != base_domain:
                continue
            ext = (parsed.path.rpartition(".")[-1] or "").lower()
            if f".{ext}" in SKIP_EXTENSIONS:
                continue

            visited.add(url)

            try:
                resp = await self.request("GET", url)
                page_count += 1
                ep = self.make_endpoint(
                    url=url, method="GET", type_hint="web_page",
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
                    p = urlparse(absolute)
                    if p.netloc and p.netloc != base_domain:
                        continue
                    if p.scheme not in ("http", "https"):
                        continue
                    norm = p.path.rstrip("/") or "/"
                    if norm in seen_normalized:
                        continue
                    seen_normalized.add(norm)
                    clean = f"{p.scheme}://{p.netloc}{norm}"
                    if clean not in visited and clean not in {u for u, _ in to_visit}:
                        to_visit.append((clean, depth + 1))

            except Exception:
                self._stats["errors"] += 1

        return findings, endpoints
