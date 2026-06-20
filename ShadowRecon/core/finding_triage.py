from datetime import datetime
from typing import Optional


FINDING_STATUSES = ["new", "confirmed", "false_positive", "accepted", "fixed", "bypassed"]


class FindingTriage:
    def __init__(self, db):
        self._db = db

    async def set_status(self, finding_id: str, status: str, note: str = ""):
        if status not in FINDING_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {FINDING_STATUSES}")
        row = await self._db._get("findings", finding_id) if hasattr(self._db, "_get") else None
        if row:
            from sqlalchemy import update
            from .database import FindingRow
            async with self._db.session() as s:
                await s.execute(
                    update(FindingRow)
                    .where(FindingRow.id == finding_id)
                    .values(status=status, remediation=note or getattr(row, "remediation", ""))
                )

    async def add_note(self, finding_id: str, author: str, text: str):
        if hasattr(self._db, "add_finding_note"):
            await self._db.add_finding_note(finding_id, author, text)

    async def get_notes(self, finding_id: str) -> list[dict]:
        if hasattr(self._db, "get_finding_notes"):
            return await self._db.get_finding_notes(finding_id)
        return []

    async def bulk_set_status(self, finding_ids: list[str], status: str):
        for fid in finding_ids:
            await self.set_status(fid, status)

    async def bulk_set_severity(self, finding_ids: list[str], severity: str):
        if hasattr(self._db, "_bulk_update"):
            await self._db._bulk_update("findings", finding_ids, {"severity": severity})
