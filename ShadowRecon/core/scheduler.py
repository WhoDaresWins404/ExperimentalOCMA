import asyncio
import json
from datetime import datetime
from typing import Optional, Callable
from pathlib import Path
import re


CRON_REGEX = re.compile(r"^(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)$")


def _match_cron(cron_expr: str, dt: datetime) -> bool:
    try:
        minute, hour, day, month, weekday = cron_expr.split()
    except ValueError:
        return False

    def _field(val: int, pattern: str) -> bool:
        return pattern == "*" or val == int(pattern)

    return (
        _field(dt.minute, minute) and
        _field(dt.hour, hour) and
        _field(dt.day, day) and
        _field(dt.month, month) and
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
        from sqlalchemy import Column, String, Text, Boolean, Integer

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
            result = await self._engine.run_scan(
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
