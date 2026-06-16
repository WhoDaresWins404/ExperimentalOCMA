import json
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Integer, Float, Boolean, DateTime, JSON, ForeignKey, select, delete, func
from sqlalchemy import UniqueConstraint, Index

from .config import ScanConfig
from .models import (
    Campaign, ScanSession, ScanStatus, Endpoint, Finding,
    GraphNode, GraphEdge, CVSSVector
)
from .exceptions import DatabaseError


class Base(DeclarativeBase):
    pass


class CampaignRow(Base):
    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[str] = mapped_column(String(32))

    sessions = relationship("ScanSessionRow", back_populates="campaign", cascade="all, delete-orphan")


class ScanSessionRow(Base):
    __tablename__ = "scan_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(32), ForeignKey("campaigns.id"))
    target: Mapped[str] = mapped_column(String(512))
    config_snapshot: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING.value)
    started_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ended_at: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    error_log: Mapped[str] = mapped_column(Text, default="[]")
    stats: Mapped[str] = mapped_column(Text, default="{}")

    campaign = relationship("CampaignRow", back_populates="sessions")
    endpoints = relationship("EndpointRow", back_populates="session", cascade="all, delete-orphan")
    findings = relationship("FindingRow", back_populates="session", cascade="all, delete-orphan")


class EndpointRow(Base):
    __tablename__ = "endpoints"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(32), ForeignKey("scan_sessions.id"))
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    type: Mapped[str] = mapped_column(String(32), default="unknown")
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    response_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    response_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    extra_data: Mapped[str] = mapped_column(Text, default="{}")
    discovered_by: Mapped[str] = mapped_column(String(64), default="")
    source: Mapped[str] = mapped_column(Text, default="")
    found_at: Mapped[str] = mapped_column(String(32))

    session = relationship("ScanSessionRow", back_populates="endpoints")

    __table_args__ = (
        Index("idx_endpoint_session_url", "session_id", "url", "method"),
    )


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(32), ForeignKey("scan_sessions.id"))
    endpoint_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    scanner_name: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="{}")
    raw_response_ids: Mapped[str] = mapped_column(Text, default="[]")
    duplicate_of: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    duplicates: Mapped[str] = mapped_column(Text, default="[]")
    is_llm_enhanced: Mapped[bool] = mapped_column(Boolean, default=False)
    llm_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="[]")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    found_at: Mapped[str] = mapped_column(String(32))

    session = relationship("ScanSessionRow", back_populates="findings")

    __table_args__ = (
        Index("idx_finding_session", "session_id"),
        Index("idx_finding_severity", "severity"),
    )


class GraphNodeRow(Base):
    __tablename__ = "graph_nodes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(32), ForeignKey("scan_sessions.id"))
    node_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(Text)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extra_data: Mapped[str] = mapped_column(Text, default="{}")


class GraphEdgeRow(Base):
    __tablename__ = "graph_edges"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(32), ForeignKey("scan_sessions.id"))
    source_node: Mapped[str] = mapped_column(String(32))
    target_node: Mapped[str] = mapped_column(String(32))
    edge_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(Text, default="")
    extra_data: Mapped[str] = mapped_column(Text, default="{}")


class DedupFingerprintRow(Base):
    __tablename__ = "dedup_fingerprints"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(32))
    fingerprint_type: Mapped[str] = mapped_column(String(32))
    fingerprint_hash: Mapped[str] = mapped_column(String(64))
    finding_id: Mapped[str] = mapped_column(String(32))

    __table_args__ = (
        Index("idx_dedup_fp", "session_id", "fingerprint_type", "fingerprint_hash"),
    )


class RawResponseRow(Base):
    __tablename__ = "raw_responses"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(32))
    url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    request_headers: Mapped[str] = mapped_column(Text, default="{}")
    request_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_headers: Mapped[str] = mapped_column(Text, default="{}")
    response_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    timing_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[str] = mapped_column(String(32))


class Database:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.engine = create_async_engine(
            config.database.url,
            echo=config.database.echo,
            pool_size=config.database.pool_size,
        )
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def initialize(self):
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self):
        await self.engine.dispose()

    @asynccontextmanager
    async def session(self):
        async with self.session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    async def _row_to_dict(self, row) -> dict:
        return {c.name: getattr(row, c.name) for c in row.__table__.columns}

    async def create_campaign(self, campaign: Campaign):
        async with self.session() as s:
            row = CampaignRow(
                id=campaign.id,
                name=campaign.name,
                description=campaign.description,
                tags=json.dumps(campaign.tags),
                created_at=campaign.created_at.isoformat(),
            )
            s.add(row)
            return campaign

    async def list_campaigns(self) -> list[Campaign]:
        async with self.session() as s:
            rows = (await s.execute(select(CampaignRow).order_by(CampaignRow.created_at.desc()))).scalars().all()
            result = []
            for row in rows:
                d = await self._row_to_dict(row)
                d["tags"] = json.loads(d["tags"])
                d["created_at"] = datetime.fromisoformat(d["created_at"])
                result.append(Campaign(**d))
            return result

    async def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        async with self.session() as s:
            row = (await s.execute(select(CampaignRow).where(CampaignRow.id == campaign_id))).scalar_one_or_none()
            if not row:
                return None
            d = await self._row_to_dict(row)
            d["tags"] = json.loads(d["tags"])
            d["created_at"] = datetime.fromisoformat(d["created_at"])
            return Campaign(**d)

    async def create_scan_session(self, session: ScanSession):
        async with self.session() as s:
            row = ScanSessionRow(
                id=session.id,
                campaign_id=session.campaign_id,
                target=session.target,
                config_snapshot=json.dumps(session.config_snapshot),
                status=session.status.value,
                started_at=session.started_at.isoformat() if session.started_at else None,
                ended_at=session.ended_at.isoformat() if session.ended_at else None,
                error_log=json.dumps(session.error_log),
            )
            s.add(row)
            return session

    async def update_scan_status(self, session_id: str, status: ScanStatus):
        async with self.session() as s:
            row = (await s.execute(select(ScanSessionRow).where(ScanSessionRow.id == session_id))).scalar_one_or_none()
            if row:
                row.status = status.value
                if status == ScanStatus.SCANNING and not row.started_at:
                    row.started_at = datetime.utcnow().isoformat()
                if status in (ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED):
                    row.ended_at = datetime.utcnow().isoformat()

    async def get_scan_session(self, session_id: str) -> Optional[dict]:
        async with self.session() as s:
            row = (await s.execute(select(ScanSessionRow).where(ScanSessionRow.id == session_id))).scalar_one_or_none()
            if not row:
                return None
            return await self._row_to_dict(row)

    async def add_endpoint(self, ep: Endpoint):
        async with self.session() as s:
            row = EndpointRow(
                id=ep.id,
                session_id=ep.session_id,
                url=ep.url,
                method=ep.method,
                type=ep.type.value,
                status_code=ep.status_code,
                content_type=ep.content_type,
                response_hash=ep.response_hash,
                response_size=ep.response_size,
                extra_data=json.dumps(ep.metadata),
                discovered_by=ep.discovered_by,
                source=ep.source,
                found_at=ep.found_at.isoformat(),
            )
            s.add(row)

    async def add_finding(self, finding: Finding):
        async with self.session() as s:
            row = FindingRow(
                id=finding.id,
                session_id=finding.session_id,
                endpoint_id=finding.endpoint_id,
                scanner_name=finding.scanner_name,
                title=finding.title,
                description=finding.description,
                severity=finding.severity.value,
                cvss_vector=finding.cvss_vector.vector_string() if finding.cvss_vector else None,
                cvss_score=finding.cvss_score,
                evidence=json.dumps(finding.evidence),
                raw_response_ids=json.dumps(finding.raw_response_ids),
                duplicate_of=finding.duplicate_of,
                duplicates=json.dumps(finding.duplicates),
                is_llm_enhanced=finding.is_llm_enhanced,
                llm_analysis=finding.llm_analysis.model_dump_json() if finding.llm_analysis else None,
                remediation=finding.remediation,
                references=json.dumps(finding.references),
                tags=json.dumps(finding.tags),
                confidence=finding.confidence,
                found_at=finding.found_at.isoformat(),
            )
            s.add(row)

    async def add_graph_node(self, node: GraphNode):
        async with self.session() as s:
            row = GraphNodeRow(
                id=node.id,
                session_id=node.session_id,
                node_type=node.node_type.value,
                label=node.label,
                url=node.url,
                extra_data=json.dumps(node.metadata),
            )
            s.add(row)

    async def add_graph_edge(self, edge: GraphEdge):
        async with self.session() as s:
            row = GraphEdgeRow(
                id=edge.id,
                session_id=edge.session_id,
                source_node=edge.source_node,
                target_node=edge.target_node,
                edge_type=edge.edge_type.value,
                label=edge.label,
                extra_data=json.dumps(edge.metadata),
            )
            s.add(row)

    async def get_session_endpoints(self, session_id: str) -> list[dict]:
        async with self.session() as s:
            rows = (await s.execute(
                select(EndpointRow).where(EndpointRow.session_id == session_id)
            )).scalars().all()
            return [await self._row_to_dict(r) for r in rows]

    async def get_session_findings(self, session_id: str) -> list[dict]:
        async with self.session() as s:
            rows = (await s.execute(
                select(FindingRow).where(FindingRow.session_id == session_id)
            )).scalars().all()
            return [await self._row_to_dict(r) for r in rows]

    async def get_session_graph(self, session_id: str) -> tuple[list[dict], list[dict]]:
        async with self.session() as s:
            nodes = (await s.execute(
                select(GraphNodeRow).where(GraphNodeRow.session_id == session_id)
            )).scalars().all()
            edges = (await s.execute(
                select(GraphEdgeRow).where(GraphEdgeRow.session_id == session_id)
            )).scalars().all()
            return [await self._row_to_dict(n) for n in nodes], [await self._row_to_dict(e) for e in edges]

    async def delete_session(self, session_id: str):
        async with self.session() as s:
            await s.execute(delete(GraphEdgeRow).where(GraphEdgeRow.session_id == session_id))
            await s.execute(delete(GraphNodeRow).where(GraphNodeRow.session_id == session_id))
            await s.execute(delete(DedupFingerprintRow).where(DedupFingerprintRow.session_id == session_id))
            await s.execute(delete(FindingRow).where(FindingRow.session_id == session_id))
            await s.execute(delete(EndpointRow).where(EndpointRow.session_id == session_id))
            await s.execute(delete(RawResponseRow).where(RawResponseRow.session_id == session_id))
            await s.execute(delete(ScanSessionRow).where(ScanSessionRow.id == session_id))

    async def get_session_count(self) -> int:
        async with self.session() as s:
            return (await s.execute(select(func.count(ScanSessionRow.id)))).scalar() or 0

    async def add_raw_response(self, data: dict):
        async with self.session() as s:
            row = RawResponseRow(**data)
            s.add(row)

    async def get_raw_responses(self, session_id: str, ids: list[str]) -> list[dict]:
        async with self.session() as s:
            rows = (await s.execute(
                select(RawResponseRow).where(
                    RawResponseRow.session_id == session_id,
                    RawResponseRow.id.in_(ids)
                )
            )).scalars().all()
            return [await self._row_to_dict(r) for r in rows]
