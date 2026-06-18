import asyncio
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Directive:
    """An instruction from IntelligenceCore to a scanner or group of scanners.

    target: scanner name or "all" for every scanner
    action: one of "augment_wordlist", "skip", "adjust_param", "enable_check"
    payload: varies by action
    reason: human-readable explanation
    priority: 0=info, 1=suggest, 2=enforce
    expires_after: max scanner runs before auto-expire (None = never)
    """
    target: str
    action: str
    payload: any = None
    reason: str = ""
    priority: int = 1
    expires_after: Optional[int] = None
    runs_left: Optional[int] = None

    def __post_init__(self):
        if self.expires_after is not None:
            self.runs_left = self.expires_after


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
