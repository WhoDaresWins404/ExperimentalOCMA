import re
from urllib.parse import urlparse, urljoin


class SpaCrawler:
    def __init__(self, pool):
        self._pool = pool

    async def crawl(self, url: str, max_pages: int = 20) -> list[dict]:
        if not self._pool.is_available:
            return []
        page = await self._pool.acquire()
        if not page:
            return []
        discovered = []
        visited = set()
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            discovered.extend(await self._extract_routes(page, url))
            links = await page.evaluate("""() => {
                const links = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    if (a.href) links.add(a.href);
                });
                return Array.from(links);
            }""")
            for link in links:
                if len(visited) >= max_pages:
                    break
                norm = self._normalize(link, url)
                if norm and norm not in visited and self._same_origin(norm, url):
                    visited.add(norm)
                    try:
                        await page.goto(norm, wait_until="networkidle", timeout=15000)
                        routes = await self._extract_routes(page, norm)
                        discovered.extend(routes)
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            await self._pool.release(page)
        return discovered

    async def _extract_routes(self, page, base_url: str) -> list[dict]:
        routes = []
        js = await page.content()
        patterns = [
            r'path:\s*["\']([^"\']+)["\']',
            r'path:\s*`([^`]+)`',
            r'route:\s*["\']([^"\']+)["\']',
            r'component:\s*["\']([^"\']+)["\']',
            r'to:\s*["\']([^"\']+)["\']',
            r'Route\s+path=["\']([^"\']+)["\']',
            r'router\.push\(["\']([^"\']+)["\']',
            r'navigate\(["\']([^"\']+)["\']',
            r'window\.location\.hash\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.pathname\s*=\s*["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            for match in re.finditer(pat, js):
                route = match.group(1)
                if route.startswith("/"):
                    full = urljoin(base_url, route)
                    if full not in {r["url"] for r in routes}:
                        routes.append({"url": full, "source": "js-route"})
        return routes

    @staticmethod
    def _normalize(link: str, base: str) -> str | None:
        try:
            full = urljoin(base, link)
            parsed = urlparse(full)
            if parsed.scheme in ("http", "https"):
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            pass
        return None

    @staticmethod
    def _same_origin(url1: str, url2: str) -> bool:
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return p1.netloc == p2.netloc
