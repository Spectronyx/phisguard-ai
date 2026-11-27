"""SQLAlchemy ORM entities for scan history."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    """One analysis request. Only a short summary of the input is persisted."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_type: Mapped[str] = mapped_column(String(16), index=True)  # email | url
    input_summary: Mapped[str] = mapped_column(String(200))
    input_hash: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(16), index=True)  # safe | suspicious | phishing
    risk_level: Mapped[str] = mapped_column(String(16), index=True)  # low | suspicious | high | critical
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    model_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    llm_used: Mapped[bool] = mapped_column(default=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    indicators: Mapped[list["ScanIndicator"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ScanIndicator.id"
    )
    components: Mapped[list["AnalysisComponent"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="AnalysisComponent.id"
    )

    __table_args__ = (Index("ix_scans_created_desc", created_at.desc()),)


class ScanIndicator(Base):
    """A single suspicious (or noteworthy) indicator attached to a scan."""

    __tablename__ = "scan_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    indicator_name: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(16))  # low | medium | high | critical
    description: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32), default="rules")

    scan: Mapped[Scan] = relationship(back_populates="indicators")


class AnalysisComponent(Base):
    """Per-module output retained for the result breakdown and history detail."""

    __tablename__ = "analysis_components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    component_name: Mapped[str] = mapped_column(String(48))
    component_status: Mapped[str] = mapped_column(String(24))
    component_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    component_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    weight: Mapped[float | None] = mapped_column(Float, nullable=True)
    contribution: Mapped[float | None] = mapped_column(Float, nullable=True)
    component_output: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="components")
