from collections import Counter, defaultdict
from datetime import datetime, timedelta


class AnalyticsEngine:
    def __init__(self, db):
        self._db = db

    async def scanner_effectiveness(self) -> list[dict]:
        sessions = await self._db._get_all("scan_sessions") if hasattr(self._db, "_get_all") else []
        findings = await self._db._get_all("findings") if hasattr(self._db, "_get_all") else []
        scanner_counts = Counter()
        scanner_sev: dict[str, Counter] = defaultdict(Counter)
        for f in findings:
            name = getattr(f, "scanner_name", "") or f.get("scanner_name", "")
            sev = getattr(f, "severity", "") or f.get("severity", "")
            scanner_counts[name] += 1
            scanner_sev[name][sev] += 1
        return [
            {"scanner": s, "total": c, "by_severity": dict(scanner_sev[s])}
            for s, c in scanner_counts.most_common()
        ]

    async def findings_over_time(self, days: int = 30) -> list[dict]:
        sessions = await self._db._get_all("scan_sessions") if hasattr(self._db, "_get_all") else []
        findings = await self._db._get_all("findings") if hasattr(self._db, "_get_all") else []
        daily = Counter()
        today = datetime.utcnow()
        cutoff = today - timedelta(days=days)
        for f in findings:
            found_at = getattr(f, "found_at", "") or f.get("found_at", "")
            try:
                dt = datetime.fromisoformat(found_at)
                if dt >= cutoff:
                    key = dt.strftime("%Y-%m-%d")
                    daily[key] += 1
            except (ValueError, TypeError):
                pass
        return [{"date": d, "count": c} for d, c in sorted(daily.items())]

    async def severity_distribution(self) -> dict[str, int]:
        findings = await self._db._get_all("findings") if hasattr(self._db, "_get_all") else []
        counts = Counter()
        for f in findings:
            sev = getattr(f, "severity", "") or f.get("severity", "")
            counts[sev] += 1
        return dict(counts)

    async def top_vulnerability_types(self, limit: int = 10) -> list[dict]:
        findings = await self._db._get_all("findings") if hasattr(self._db, "_get_all") else []
        type_counts = Counter()
        for f in findings:
            title = getattr(f, "title", "") or f.get("title", "")
            tag = title.split("—")[0].strip() if "—" in title else title.split(":")[0].strip() if ":" in title else title[:60]
            type_counts[tag] += 1
        return [{"type": t, "count": c} for t, c in type_counts.most_common(limit)]
