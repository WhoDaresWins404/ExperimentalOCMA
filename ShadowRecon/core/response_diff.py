import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ResponseSnapshot:
    url: str
    method: str
    status_code: int
    headers: dict
    body_hash: str
    body_preview: str

    @staticmethod
    def from_httpx_response(url: str, method: str, response) -> "ResponseSnapshot":
        body = response.text or ""
        return ResponseSnapshot(
            url=url,
            method=method,
            status_code=response.status_code,
            headers=dict(response.headers),
            body_hash=hashlib.sha256(body.encode()).hexdigest()[:16],
            body_preview=body[:500],
        )


@dataclass
class DiffResult:
    url: str
    method: str
    has_diff: bool
    status_changed: bool
    size_delta: int
    new_content: list[str]
    missing_content: list[str]
    diff_type: str = "unknown"

    @property
    def is_notable(self) -> bool:
        return self.has_diff and (
            self.status_changed or abs(self.size_delta) > 100
        )


def diff_snapshots(baseline: ResponseSnapshot, secondary: ResponseSnapshot) -> DiffResult:
    status_changed = baseline.status_code != secondary.status_code
    size_delta = len(secondary.body_preview) - len(baseline.body_preview)
    baseline_lines = set(baseline.body_preview.splitlines())
    secondary_lines = set(secondary.body_preview.splitlines())
    new_content = [l for l in secondary_lines - baseline_lines if l.strip()]
    missing_content = [l for l in baseline_lines - secondary_lines if l.strip()]
    has_diff = status_changed or bool(new_content) or bool(missing_content)
    diff_type = "status" if status_changed else "content" if has_diff else "identical"
    return DiffResult(
        url=baseline.url,
        method=baseline.method,
        has_diff=has_diff,
        status_changed=status_changed,
        size_delta=size_delta,
        new_content=new_content[:20],
        missing_content=missing_content[:20],
        diff_type=diff_type,
    )


class ResponseDiffEngine:
    def __init__(self):
        self._baselines: dict[str, ResponseSnapshot] = {}

    def _key(self, url: str, method: str) -> str:
        return f"{method}:{url}"

    def record_baseline(self, snapshot: ResponseSnapshot):
        self._baselines[self._key(snapshot.url, snapshot.method)] = snapshot

    def compare(self, secondary: ResponseSnapshot) -> Optional[DiffResult]:
        baseline = self._baselines.get(self._key(secondary.url, secondary.method))
        if baseline is None:
            return None
        return diff_snapshots(baseline, secondary)
