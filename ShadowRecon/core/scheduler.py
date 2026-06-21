from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .models import ScanProfile, Directive, ScanTarget
from .budget import TimeBudgetManager
from .directive import DirectiveBus
from .config import ScanConfig
from scanners.base import BaseScanner
from core.exceptions import ScanCancelled, HostUnreachable


@dataclass(order=True)
class ScannerJob:
    priority: int
    name: str = field(compare=False)
    scanner: BaseScanner = field(compare=False)
    dependencies: list[str] = field(default_factory=list, compare=False)
    time_budget: int = field(default=120, compare=False)


class PriorityScheduler:
    def __init__(
        self,
        scanners: dict[str, BaseScanner],
        budget_mgr: TimeBudgetManager,
        directive_bus: DirectiveBus,
        config: ScanConfig,
        host_monitor=None,
    ):
        self._scanners = scanners
        self._budget = budget_mgr
        self._bus = directive_bus
        self._config = config
        self._host_monitor = host_monitor
        self._queue: list[ScannerJob] = []
        self._completed: set[str] = set()
        self._cancelled = False

    def build_from_profile(self, profile: ScanProfile, mode: str):
        if mode == "light":
            order = ["crawler_scanner", "directory_scanner", "misconfig_scanner"]
        elif mode == "waf_only":
            order = []
        else:
            order = ["crawler_scanner", "api_scanner", "directory_scanner",
                     "misconfig_scanner", "anomaly_detector", "form_scanner"]

        for name in order:
            if name not in self._scanners:
                continue
            if name in profile.skipped_scanners:
                continue
            base_priority = profile.scanner_priorities.get(name, 50)
            job = ScannerJob(
                priority=base_priority,
                name=name,
                scanner=self._scanners[name],
                time_budget=self._budget.allocate(name, weight=0.15),
            )
            self._queue.append(job)

        queued = {j.name for j in self._queue}
        for name in self._scanners:
            if name in queued or name in profile.skipped_scanners:
                continue
            if mode in ("waf_only", "light"):
                continue
            job = ScannerJob(
                priority=profile.scanner_priorities.get(name, 60),
                name=name,
                scanner=self._scanners[name],
                time_budget=self._budget.allocate(name, weight=0.08),
            )
            self._queue.append(job)

        self._queue.sort(key=lambda j: j.priority)

    async def run_next(self, target: ScanTarget) -> Optional[tuple[str, tuple]]:
        if self._cancelled:
            raise ScanCancelled()
        if self._host_monitor and self._host_monitor.is_dead:
            raise HostUnreachable(target.url, self._host_monitor.unreachable_for)

        while self._queue:
            job = self._queue.pop(0)

            if job.name in self._completed:
                continue

            deps_met = all(dep in self._completed for dep in job.dependencies)
            if not deps_met and job.dependencies:
                self._queue.append(job)
                continue

            skip_dirs = await self._bus.consume(job.name)
            if any(d.action == "skip" for d in skip_dirs):
                self._completed.add(job.name)
                continue
            if skip_dirs:
                non_skip = [d for d in skip_dirs if d.action != "skip"]
                if non_skip:
                    await self._bus.issue_many(non_skip)

            scanner = job.scanner
            consume = await self._bus.consume(scanner.name)
            for d in consume:
                if d.action == "augment_wordlist" and isinstance(d.payload, list):
                    if hasattr(scanner, "_augmented_paths"):
                        scanner._augmented_paths = (scanner._augmented_paths or []) + d.payload
                    else:
                        scanner._augmented_paths = d.payload
                elif d.action == "adjust_param" and isinstance(d.payload, dict):
                    for k, v in d.payload.items():
                        if hasattr(scanner.config, k):
                            setattr(scanner.config, k, v)
                        elif k == "evasion_headers" and hasattr(scanner, "waf_state"):
                            scanner.waf_state.update(v)

            try:
                findings, endpoints = await asyncio.wait_for(
                    scanner.scan(target),
                    timeout=job.time_budget,
                )
                self._completed.add(job.name)
                self._budget.surplus(job.name, job.time_budget)
            except asyncio.TimeoutError:
                findings, endpoints = [], []
                self._completed.add(job.name)
                self._budget.surplus(job.name, job.time_budget)
            except Exception:
                findings, endpoints = [], []
                self._completed.add(job.name)
            finally:
                await scanner.cleanup()

            return job.name, (findings, endpoints)

        return None

    async def reprioritize(self, scanner_name: str, new_priority: int):
        for job in self._queue:
            if job.name == scanner_name and job.name not in self._completed:
                job.priority = new_priority
        self._queue.sort(key=lambda j: j.priority)

    async def grant_emergency_time(self, scanner_name: str, amount: int) -> bool:
        for job in self._queue:
            if job.name == scanner_name and job.name not in self._completed:
                return self._budget.emergency_fund(scanner_name, amount)
        return False

    def cancel(self):
        self._cancelled = True

    @property
    def completed(self) -> list[str]:
        return list(self._completed)

    @property
    def pending(self) -> list[str]:
        return [j.name for j in self._queue if j.name not in self._completed]


def _match_cron(cron_expr: str, dt: datetime) -> bool:
    try:
        minute, hour, day, month, weekday = cron_expr.split()
    except ValueError:
        return False
    def _field(val: int, pattern: str) -> bool:
        return pattern == "*" or val == int(pattern)
    return (
        _field(dt.minute, minute) and _field(dt.hour, hour) and
        _field(dt.day, day) and _field(dt.month, month) and
        _field(dt.weekday(), weekday if weekday != "*" else "*")
    )


class ScanScheduler:
    def __init__(self, engine, check_interval: int = 60):
        self._engine = engine
        self._interval = check_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None

    async def _loop(self):
        while self._running:
            try:
                await self._check_schedules()
            except Exception:
                pass
            await asyncio.sleep(self._interval)

    async def _check_schedules(self):
        now = datetime.utcnow()
        schedules = await self._get_schedules()
        for sched in schedules:
            if not sched.get("enabled", True):
                continue
            last = sched.get("last_run", "")
            try:
                last_dt = datetime.fromisoformat(last) if last else datetime.min
            except (ValueError, TypeError):
                last_dt = datetime.min
            if _match_cron(sched.get("cron", ""), now):
                if (now - last_dt).total_seconds() >= 60:
                    await self._execute(sched)

    async def _get_schedules(self) -> list[dict]:
        from sqlalchemy import select
        from .database import Base
        from sqlalchemy import Column, String, Text, Boolean

        if not hasattr(self._engine.db, "_schedule_table_created"):
            class ScanScheduleRow(Base):
                __tablename__ = "scan_schedules"
                id = Column(String(32), primary_key=True)
                target = Column(String(512), nullable=False)
                campaign_id = Column(String(32), nullable=False)
                cron = Column(String(64), nullable=False)
                config_snapshot = Column(Text, default="{}")
                enabled = Column(Boolean, default=True)
                last_run = Column(String(32), default="")

            self._engine.db._schedule_table_created = True
            async with self._engine.db.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        async with self._engine.db.session() as s:
            rows = (await s.execute(select(ScanScheduleRow))).scalars().all()
            return [
                {"id": r.id, "target": r.target, "campaign_id": r.campaign_id,
                 "cron": r.cron, "enabled": r.enabled, "last_run": r.last_run,
                 "config_snapshot": json.loads(r.config_snapshot) if r.config_snapshot else {}}
                for r in rows
            ]

    async def _execute(self, schedule: dict):
        try:
            config = schedule.get("config_snapshot", {})
            await self._engine.run_scan(
                schedule["campaign_id"], schedule["target"],
                config_override=config,
            )
            from sqlalchemy import update
            async with self._engine.db.session() as s:
                await s.execute(
                    update(type("R", (), {"__tablename__": "scan_schedules"}))
                    .where(type("R", (), {"id": schedule["id"]}).id == schedule["id"])
                    .values(last_run=datetime.utcnow().isoformat())
                )
        except Exception:
            pass
