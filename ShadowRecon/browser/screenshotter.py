from pathlib import Path
from urllib.parse import urlparse


class Screenshotter:
    def __init__(self, pool, output_dir: str = "screenshots"):
        self._pool = pool
        self._output_dir = Path(output_dir)

    async def capture(self, url: str) -> str | None:
        if not self._pool.is_available:
            return None
        page = await self._pool.acquire()
        if not page:
            return None
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            self._output_dir.mkdir(parents=True, exist_ok=True)
            parsed = urlparse(url)
            safe_name = f"{parsed.netloc}{parsed.path.replace('/', '_')}"[:100] or "index"
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in safe_name)
            path = self._output_dir / f"{safe_name}.png"
            await page.screenshot(path=str(path), full_page=True)
            return str(path)
        except Exception:
            return None
        finally:
            await self._pool.release(page)
