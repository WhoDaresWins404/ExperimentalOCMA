from datetime import datetime
from typing import Optional


class KnowledgeBase:
    def __init__(self, db):
        self._db = db

    async def search_findings(self, query: str = "", scanner: str = "", severity: str = "",
                              tag: str = "", status: str = "", limit: int = 100, offset: int = 0) -> list[dict]:
        from sqlalchemy import select, or_, and_
        from .database import FindingRow

        async with self._db.session() as s:
            stmt = select(FindingRow)
            conditions = []
            if query:
                like = f"%{query}%"
                conditions.append(or_(
                    FindingRow.title.ilike(like),
                    FindingRow.description.ilike(like),
                ))
            if scanner:
                conditions.append(FindingRow.scanner_name == scanner)
            if severity:
                conditions.append(FindingRow.severity == severity)
            if tag:
                conditions.append(FindingRow.tags.ilike(f"%{tag}%"))
            if status:
                conditions.append(FindingRow.__table__.c.get("status", FindingRow.severity).as_string() == status)

            if conditions:
                stmt = stmt.where(and_(*conditions))
            stmt = stmt.order_by(FindingRow.cvss_score.desc().nullslast()).offset(offset).limit(limit)
            rows = (await s.execute(stmt)).scalars().all()
            return [await self._db._row_to_dict(r) for r in rows]

    async def add_comment(self, finding_id: str, author: str, text: str):
        from .database import Base
        from sqlalchemy import Column, String, Text, DateTime, ForeignKey

        if not hasattr(self._db, "_comment_table_created"):
            class FindingComment(Base):
                __tablename__ = "finding_comments"
                id = Column(String(32), primary_key=True)
                finding_id = Column(String(32), ForeignKey("findings.id"), nullable=False)
                author = Column(String(64), default="")
                text = Column(Text, nullable=False)
                created_at = Column(String(32))

            self._db._comment_table_created = True
            async with self._db.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        import uuid
        async with self._db.session() as s:
            comment = FindingComment(
                id=uuid.uuid4().hex[:12],
                finding_id=finding_id,
                author=author,
                text=text,
                created_at=datetime.utcnow().isoformat(),
            )
            s.add(comment)

    async def get_comments(self, finding_id: str) -> list[dict]:
        from sqlalchemy import select
        from .database import Base
        from sqlalchemy import Column, String, Text, DateTime

        if not hasattr(self._db, "_comment_table_created"):
            return []

        class FindingComment(Base):
            __tablename__ = "finding_comments"
            id = Column(String(32), primary_key=True)
            finding_id = Column(String(32), nullable=False)
            author = Column(String(64), default="")
            text = Column(Text, nullable=False)
            created_at = Column(String(32))

        async with self._db.session() as s:
            rows = (await s.execute(
                select(FindingComment).where(FindingComment.finding_id == finding_id).order_by(FindingComment.created_at)
            )).scalars().all()
            return [{"id": r.id, "author": r.author, "text": r.text, "created_at": r.created_at} for r in rows]
