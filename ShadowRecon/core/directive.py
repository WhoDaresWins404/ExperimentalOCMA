import asyncio
from typing import Optional

from .models import Directive


class DirectiveBus:
    """Thread-safe bus for issuing and consuming directives mid-scan."""

    def __init__(self):
        self._directives: list[Directive] = []
        self._lock = asyncio.Lock()

    async def issue(self, d: Directive):
        async with self._lock:
            self._directives.append(d)

    async def issue_many(self, directives: list[Directive]):
        async with self._lock:
            self._directives.extend(directives)

    async def consume(self, scanner_name: str) -> list[Directive]:
        """Return all directives targeting this scanner (or 'all'), removing expired ones."""
        async with self._lock:
            hits: list[Directive] = []
            remaining: list[Directive] = []

            for d in self._directives:
                if d.target in (scanner_name, "all"):
                    hits.append(d)
                    if d.runs_left is not None:
                        d.runs_left -= 1
                        if d.runs_left > 0:
                            remaining.append(d)
                    elif d.expires_after is None:
                        remaining.append(d)
                else:
                    remaining.append(d)

            self._directives = remaining
            return hits

    async def peek(self, scanner_name: str) -> list[Directive]:
        """Look at directives without consuming them."""
        async with self._lock:
            return [d for d in self._directives if d.target in (scanner_name, "all")]

    async def clear(self):
        async with self._lock:
            self._directives.clear()

    async def count(self) -> int:
        async with self._lock:
            return len(self._directives)
