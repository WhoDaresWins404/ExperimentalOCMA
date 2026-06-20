import asyncio
from typing import Optional


class PlaywrightPool:
    def __init__(self, headless: bool = True, pool_size: int = 2):
        self._headless = headless
        self._pool_size = pool_size
        self._browser = None
        self._contexts: list = []
        self._pages: list = []
        self._lock = asyncio.Lock()
        self._available: asyncio.Queue = asyncio.Queue()

    async def start(self):
        try:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=self._headless)
            for _ in range(self._pool_size):
                ctx = await self._browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ShadowRecon/1.0",
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )
                page = await ctx.new_page()
                self._contexts.append(ctx)
                self._pages.append(page)
                await self._available.put(page)
        except ImportError:
            self._browser = None

    @property
    def is_available(self) -> bool:
        return self._browser is not None

    async def acquire(self) -> Optional["Page"]:
        if not self.is_available:
            return None
        try:
            return await asyncio.wait_for(self._available.get(), timeout=30.0)
        except asyncio.TimeoutError:
            return None

    async def release(self, page):
        if page:
            await self._available.put(page)

    async def stop(self):
        if self._browser:
            for ctx in self._contexts:
                try:
                    await ctx.close()
                except Exception:
                    pass
            await self._browser.close()
            await self._pw.stop()
            self._browser = None
