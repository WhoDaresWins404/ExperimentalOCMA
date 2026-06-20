import re
from urllib.parse import urljoin


DOM_SINKS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln",
    "eval", "setTimeout", "setInterval", "new Function",
    "location.href", "location.replace", "location.assign",
    "document.location", "window.location",
    "srcdoc", "domain", "document.open",
]

XSS_PROBES = [
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "\"-alert(1)-\"",
    "'-alert(1)-'",
]


class DomXssDetector:
    def __init__(self, pool):
        self._pool = pool

    async def scan(self, url: str) -> list[dict]:
        if not self._pool.is_available:
            return []
        page = await self._pool.acquire()
        if not page:
            return []
        results = []
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            html = await page.content()

            for sink in DOM_SINKS:
                pattern = re.compile(re.escape(sink), re.IGNORECASE)
                for match in pattern.finditer(html):
                    start = max(0, match.start() - 100)
                    end = min(len(html), match.end() + 100)
                    context = html[start:end]
                    results.append({
                        "type": "sink-found",
                        "sink": sink,
                        "context": context,
                        "severity": "high" if sink in ("eval", "setTimeout", "setInterval", "new Function") else "medium",
                    })

            for probe in XSS_PROBES:
                try:
                    await page.evaluate(f"document.body.innerHTML += {repr(probe)}")
                    if await page.evaluate(f"document.body.innerHTML.includes({repr(probe[:20])})"):
                        results.append({
                            "type": "injection-success",
                            "payload": probe,
                            "sink": "innerHTML",
                            "severity": "critical",
                        })
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            await self._pool.release(page)
        return results
