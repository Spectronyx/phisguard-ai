"""Scan persistence, history queries and dashboard statistics."""

from __future__ import annotations

import math
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings
from app.models.scan import AnalysisComponent, Scan, ScanIndicator


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class ScanService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # ------------------------------------------------------------------
    def create(self, db: Session, result: dict[str, Any]) -> Scan:
        scan = Scan(
            scan_type=result["scan_type"],
            input_summary=result["input_summary"],
            input_hash=result.get("input_hash", ""),
            classification=result["classification"],
            risk_level=result["risk_level"],
            risk_score=int(result["risk_score"]),
            model_confidence=result.get("model_confidence"),
            explanation=result["explanation"],
            recommendation=result["recommendation"],
            llm_used=bool(result.get("llm_used")),
            details=result.get("details", {}),
            created_at=_utc(result.get("created_at")) or datetime.now(timezone.utc),
        )
        db.add(scan)
        db.flush()

        for indicator in result.get("indicators", []):
            db.add(ScanIndicator(
                scan_id=scan.id,
                indicator_name=indicator["name"][:120],
                severity=indicator.get("severity", "low"),
                description=indicator.get("description", ""),
                source=indicator.get("source", "rules")[:32],
            ))

        for component in result.get("components", []):
            db.add(AnalysisComponent(
                scan_id=scan.id,
                component_name=component["name"][:48],
                component_status=component.get("status", "unavailable")[:24],
                component_score=component.get("score"),
                component_confidence=component.get("confidence"),
                weight=component.get("weight"),
                contribution=component.get("contribution"),
                component_output={"details": component.get("details", {})},
            ))
        db.commit()
        db.refresh(scan)
        return scan

    # ------------------------------------------------------------------
    def to_response(self, scan: Scan) -> dict[str, Any]:
        return {
            "scan_id": scan.id,
            "scan_type": scan.scan_type,
            "input_summary": scan.input_summary,
            "classification": scan.classification,
            "risk_level": scan.risk_level,
            "risk_score": scan.risk_score,
            "model_confidence": scan.model_confidence,
            "indicators": [
                {
                    "name": i.indicator_name,
                    "severity": i.severity,
                    "description": i.description,
                    "source": i.source,
                }
                for i in scan.indicators
            ],
            "components": [
                {
                    "name": c.component_name,
                    "label": _COMPONENT_LABELS.get(c.component_name, c.component_name),
                    "status": c.component_status,
                    "score": c.component_score,
                    "confidence": c.component_confidence,
                    "weight": c.weight,
                    "contribution": c.contribution,
                    "explanation": _component_explanation(scan, c),
                    "details": (c.component_output or {}).get("details", {}),
                }
                for c in scan.components
            ],
            "explanation": scan.explanation,
            "recommendation": scan.recommendation,
            "llm_used": scan.llm_used,
            "llm_sent_to_provider": bool((scan.details or {}).get("pipeline", {}).get("llm_sent_to_provider")),
            "created_at": _utc(scan.created_at),
            "details": scan.details or {},
            "url_results": [],
        }

    def get(self, db: Session, scan_id: int) -> dict[str, Any] | None:
        scan = db.execute(
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.indicators), selectinload(Scan.components))
        ).scalar_one_or_none()
        return self.to_response(scan) if scan else None

    # ------------------------------------------------------------------
    def list_scans(
        self,
        db: Session,
        page: int = 1,
        page_size: int = 20,
        search: str | None = None,
        classification: str | None = None,
        scan_type: str | None = None,
    ) -> dict[str, Any]:
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        conditions = []
        if search:
            pattern = f"%{search.strip()}%"
            conditions.append(or_(Scan.input_summary.ilike(pattern), Scan.explanation.ilike(pattern)))
        if classification:
            conditions.append(Scan.classification == classification)
        if scan_type:
            conditions.append(Scan.scan_type == scan_type)

        count_stmt = select(func.count(Scan.id))
        if conditions:
            count_stmt = count_stmt.where(*conditions)
        total = int(db.execute(count_stmt).scalar() or 0)

        stmt = (
            select(Scan)
            .options(selectinload(Scan.indicators))
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        if conditions:
            stmt = stmt.where(*conditions)
        scans = db.execute(stmt).scalars().all()
        items = [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "input_summary": s.input_summary,
                "classification": s.classification,
                "risk_level": s.risk_level,
                "risk_score": s.risk_score,
                "model_confidence": s.model_confidence,
                "llm_used": s.llm_used,
                "indicator_count": len(s.indicators),
                "created_at": _utc(s.created_at),
            }
            for s in scans
        ]
        pages = math.ceil(total / page_size) if total else 0
        return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": pages}

    # ------------------------------------------------------------------
    def stats(self, db: Session) -> dict[str, Any]:
        total = int(db.execute(select(func.count(Scan.id))).scalar() or 0)
        by_class = dict(db.execute(
            select(Scan.classification, func.count(Scan.id)).group_by(Scan.classification)
        ).all())
        by_type = dict(db.execute(
            select(Scan.scan_type, func.count(Scan.id)).group_by(Scan.scan_type)
        ).all())
        avg = db.execute(select(func.avg(Scan.risk_score))).scalar()
        critical = int(db.execute(
            select(func.count(Scan.id)).where(Scan.risk_level == "critical")
        ).scalar() or 0)
        llm_count = int(db.execute(
            select(func.count(Scan.id)).where(Scan.llm_used.is_(True))
        ).scalar() or 0)

        recent = db.execute(
            select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(6)
        ).scalars().all()

        top_indicators = db.execute(
            select(ScanIndicator.indicator_name, func.count(ScanIndicator.id).label("count"))
            .group_by(ScanIndicator.indicator_name)
            .order_by(func.count(ScanIndicator.id).desc())
            .limit(6)
        ).all()

        return {
            "total_scans": total,
            "phishing_detections": int(by_class.get("phishing", 0)),
            "suspicious_detections": int(by_class.get("suspicious", 0)),
            "safe_detections": int(by_class.get("safe", 0)),
            "critical_detections": critical,
            "average_risk_score": round(float(avg or 0.0), 1),
            "email_scans": int(by_type.get("email", 0)),
            "url_scans": int(by_type.get("url", 0)),
            "llm_assisted_scans": llm_count,
            "recent_scans": [
                {
                    "id": s.id,
                    "scan_type": s.scan_type,
                    "input_summary": s.input_summary,
                    "classification": s.classification,
                    "risk_level": s.risk_level,
                    "risk_score": s.risk_score,
                    "created_at": _utc(s.created_at),
                }
                for s in recent
            ],
            "distribution": [
                {"name": "Safe", "value": int(by_class.get("safe", 0))},
                {"name": "Suspicious", "value": int(by_class.get("suspicious", 0))},
                {"name": "Phishing", "value": int(by_class.get("phishing", 0))},
            ],
            "top_indicators": [
                {"name": name, "count": int(count)} for name, count in top_indicators
            ],
        }

    # ------------------------------------------------------------------
    def trend(self, db: Session, days: int = 14) -> dict[str, Any]:
        days = max(1, min(days, 90))
        start = datetime.now(timezone.utc).date() - timedelta(days=days - 1)
        raw = db.execute(
            select(
                func.date(Scan.created_at).label("day"),
                func.count(Scan.id).label("scans"),
                func.avg(Scan.risk_score).label("avg_risk"),
            )
            .where(func.date(Scan.created_at) >= start.isoformat())
            .group_by(func.date(Scan.created_at))
        ).all()
        phishing_rows = db.execute(
            select(func.date(Scan.created_at).label("day"), func.count(Scan.id))
            .where(func.date(Scan.created_at) >= start.isoformat())
            .where(Scan.classification == "phishing")
            .group_by(func.date(Scan.created_at))
        ).all()
        phishing_by_day = {str(day): int(count) for day, count in phishing_rows}
        by_day = {
            str(day): {"scans": int(scans), "average_risk_score": round(float(avg or 0), 1)}
            for day, scans, avg in raw
        }

        points = []
        for offset in range(days):
            day: date = start + timedelta(days=offset)
            key = day.isoformat()
            point = by_day.get(key, {"scans": 0, "average_risk_score": 0.0})
            points.append({
                "date": key,
                "scans": point["scans"],
                "phishing": phishing_by_day.get(key, 0),
                "average_risk_score": point["average_risk_score"],
            })
        return {"days": days, "points": points}


_COMPONENT_LABELS = {
    "email_model": "Email NLP classifier",
    "url_model": "URL ML classifier",
    "email_rules": "Email social-engineering rules",
    "url_rules": "URL rule engine",
    "graph": "Domain relationship graph",
    "llm": "LLM semantic analysis",
}


def _component_explanation(scan: Scan, component: AnalysisComponent) -> str:
    """Reconstruct a short explanation for history views."""
    details = (component.component_output or {}).get("details", {})
    if component.component_status != "ok":
        return {
            "unavailable": "This module was not available for this scan.",
            "no_data": "No matching data was available for this module.",
            "skipped": "This module was not applicable to this scan.",
            "error": "This module failed during the scan; other modules continued.",
            "degraded": "This module ran in degraded mode.",
        }.get(component.component_status, "")
    if component.component_name == "email_model":
        prob = details.get("probability")
        if prob is not None:
            return (
                f"The email classifier estimated a {float(prob) * 100:.1f}% phishing probability "
                f"({details.get('algorithm', 'model')})."
            )
    if component.component_name == "url_model":
        prob = details.get("probability")
        if prob is not None:
            return (
                f"The URL classifier estimated a {float(prob) * 100:.1f}% malicious probability "
                f"for the highest-risk URL."
            )
    if component.component_name == "graph":
        return "Graph evidence from the local domain corpus."
    return f"{_COMPONENT_LABELS.get(component.component_name, component.component_name)} produced a risk score."
