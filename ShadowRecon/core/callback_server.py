import asyncio
from asyncio import Server
from typing import Optional


class SSRFCallbackServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self._server: Optional[Server] = None
        self._callbacks: list[dict] = []
        self._running = False

    async def _handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        data = await reader.read(4096)
        request_line = data.decode("utf-8", errors="replace").split("\r\n")[0]
        method, path, *_ = request_line.split(" ")
        peername = writer.get_extra_info("peername")
        self._callbacks.append({
            "method": method,
            "path": path,
            "remote": f"{peername[0]}:{peername[1]}" if peername else "unknown",
            "raw": data.decode("utf-8", errors="replace")[:500],
        })
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        await writer.drain()
        writer.close()

    async def start(self):
        self._server = await asyncio.start_server(self._handler, self.host, self.port)
        self._running = True

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    @property
    def callback_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    @property
    def callbacks(self) -> list[dict]:
        return list(self._callbacks)

    def drain(self):
        self._callbacks.clear()
