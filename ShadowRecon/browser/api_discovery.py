import json
import re
from urllib.parse import urljoin, urlparse


class ApiDiscovery:
    def __init__(self, pool):
        self._pool = pool

    async def discover(self, url: str) -> list[dict]:
        if not self._pool.is_available:
            return []
        page = await self._pool.acquire()
        if not page:
            return []
        discovered = []
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)

            api_calls = await page.evaluate("""() => {
                const calls = [];
                const origFetch = window.fetch;
                window.fetch = function() { calls.push({method: arguments[1]?.method || 'GET', url: arguments[0]}); return origFetch.apply(this, arguments); };
                const origXhr = window.XMLHttpRequest;
                if (origXhr) {
                    const OrigOpen = origXhr.prototype.open;
                    origXhr.prototype.open = function(method, url) { calls.push({method: method, url: url, xhr: true}); return OrigOpen.apply(this, arguments); };
                }
                return calls;
            }""")

            html = await page.content()
            js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
            for js_url in js_urls:
                full_js_url = urljoin(url, js_url)
                discovered.append({"type": "script", "url": full_js_url, "source": "html-script-tag"})

            for call in (api_calls or []):
                call_url = call.get("url", "")
                if call_url and not call_url.startswith("data:") and not call_url.startswith("blob:"):
                    full_url = urljoin(url, call_url) if not call_url.startswith("http") else call_url
                    discovered.append({
                        "type": "api-call",
                        "url": full_url,
                        "method": call.get("method", "GET"),
                        "source": "xhr" if call.get("xhr") else "fetch",
                    })

        except Exception:
            pass
        finally:
            await self._pool.release(page)
        return discovered
