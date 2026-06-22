import asyncio
import json
from pathlib import Path
from typing import Iterable, Iterator, Any

from core.models import Finding, Endpoint


class DiskBuffer:
    def __init__(self, session_id: str, tmp_dir: str = "data/tmp"):
        self.session_id = session_id
        self._dir = Path(tmp_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._f_path = self._dir / f"scan_{session_id}_findings.jsonl"
        self._e_path = self._dir / f"scan_{session_id}_endpoints.jsonl"
        self._x_path = self._dir / f"scan_{session_id}_exchanges.jsonl"
        self._lock = asyncio.Lock()

    async def write_findings(self, findings: Iterable[Finding]):
        lines = [f.model_dump_json() for f in findings]
        if not lines:
            return
        async with self._lock:
            with open(self._f_path, "a", encoding="utf-8") as f:
                for line in lines:
                    f.write(line + "\n")

    async def write_endpoints(self, endpoints: Iterable[Endpoint]):
        lines = [ep.model_dump_json() for ep in endpoints]
        if not lines:
            return
        async with self._lock:
            with open(self._e_path, "a", encoding="utf-8") as f:
                for line in lines:
                    f.write(line + "\n")

    async def write_finding(self, finding: Finding):
        await self.write_findings([finding])

    async def write_endpoint(self, endpoint: Endpoint):
        await self.write_endpoints([endpoint])

    async def write_exchange(self, data: dict):
        line = json.dumps(data, default=str)
        async with self._lock:
            with open(self._x_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def read_findings(self, limit: int = None) -> Iterator[Finding]:
        if not self._f_path.exists():
            return
        with open(self._f_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if limit is not None and i >= limit:
                    break
                line = line.strip()
                if line:
                    yield Finding.model_validate_json(line)

    def read_endpoints(self, limit: int = None) -> Iterator[Endpoint]:
        if not self._e_path.exists():
            return
        with open(self._e_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if limit is not None and i >= limit:
                    break
                line = line.strip()
                if line:
                    yield Endpoint.model_validate_json(line)

    def read_exchanges(self, limit: int = None) -> Iterator[dict]:
        if not self._x_path.exists():
            return
        with open(self._x_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if limit is not None and i >= limit:
                    break
                line = line.strip()
                if line:
                    yield json.loads(line)

    def count_exchanges(self) -> int:
        if not self._x_path.exists():
            return 0
        with open(self._x_path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    def count_findings(self) -> int:
        if not self._f_path.exists():
            return 0
        with open(self._f_path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    def count_endpoints(self) -> int:
        if not self._e_path.exists():
            return 0
        with open(self._e_path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    async def cleanup(self):
        for p in [self._f_path, self._e_path, self._x_path]:
            if p.exists():
                p.unlink(missing_ok=True)
