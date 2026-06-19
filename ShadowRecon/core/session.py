from datetime import datetime
from typing import Optional

from .database import Database
from .models import Campaign, ScanSession, ScanStatus


class CampaignManager:
    def __init__(self, db: Database):
        self.db = db

    async def create(self, name: str, description: str = "", tags: list[str] = None) -> Campaign:
        campaign = Campaign(name=name, description=description, tags=tags or [])
        await self.db.create_campaign(campaign)
        return campaign

    async def list_all(self) -> list[Campaign]:
        return await self.db.list_campaigns()

    async def get(self, campaign_id: str) -> Optional[Campaign]:
        return await self.db.get_campaign(campaign_id)

    async def delete(self, campaign_id: str):
        async with self.db.session() as s:
            from .database import CampaignRow, select, delete
            await s.execute(delete(CampaignRow).where(CampaignRow.id == campaign_id))


class ScanSessionManager:
    def __init__(self, db: Database):
        self.db = db

    async def create(
        self, campaign_id: str, target: str, config_snapshot: dict = None,
        continue_from: str = None,
    ) -> ScanSession:
        session = ScanSession(
            campaign_id=campaign_id,
            target=target,
            config_snapshot=config_snapshot or {},
            status=ScanStatus.PENDING,
            continue_from=continue_from,
        )
        await self.db.create_scan_session(session)
        return session

    async def update_status(self, session_id: str, status: ScanStatus):
        await self.db.update_scan_status(session_id, status)

    async def get(self, session_id: str) -> Optional[dict]:
        return await self.db.get_scan_session(session_id)

    async def add_error(self, session_id: str, error: str):
        session = await self.get(session_id)
        if session:
            errors = session.get("error_log", "[]")
            import json
            err_list = json.loads(errors)
            err_list.append(f"[{datetime.utcnow().isoformat()}] {error}")
            async with self.db.session() as s:
                from .database import ScanSessionRow, select
                row = (await s.execute(
                    select(ScanSessionRow).where(ScanSessionRow.id == session_id)
                )).scalar_one_or_none()
                if row:
                    row.error_log = json.dumps(err_list)

    async def update_stats(self, session_id: str, stats: dict):
        import json
        async with self.db.session() as s:
            from .database import ScanSessionRow, select
            row = (await s.execute(
                select(ScanSessionRow).where(ScanSessionRow.id == session_id)
            )).scalar_one_or_none()
            if row:
                row.stats = json.dumps(stats)

    async def update_scanner_state(self, session_id: str, scanner_state: dict):
        import json
        async with self.db.session() as s:
            from .database import ScanSessionRow, select
            row = (await s.execute(
                select(ScanSessionRow).where(ScanSessionRow.id == session_id)
            )).scalar_one_or_none()
            if row:
                row.scanner_state = json.dumps(scanner_state)

    async def finalize(self, session_id: str, status: ScanStatus = ScanStatus.COMPLETED):
        await self.db.update_scan_status(session_id, status)

    async def get_campaign_sessions(self, campaign_id: str) -> list[dict]:
        async with self.db.session() as s:
            from .database import ScanSessionRow, select
            rows = (await s.execute(
                select(ScanSessionRow).where(
                    ScanSessionRow.campaign_id == campaign_id
                ).order_by(ScanSessionRow.started_at.desc())
            )).scalars().all()
            return [await self.db._row_to_dict(r) for r in rows]
