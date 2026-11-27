"""Dashboard statistics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_scan_service
from app.schemas.history import DashboardStats, TrendResponse
from app.services.scan_service import ScanService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats, summary="Aggregate dashboard statistics")
def dashboard_stats(
    scans: ScanService = Depends(get_scan_service),
    db: Session = Depends(get_db),
) -> DashboardStats:
    return DashboardStats.model_validate(scans.stats(db))


@router.get("/trend", response_model=TrendResponse, summary="Daily scan trend")
def dashboard_trend(
    days: int = Query(14, ge=1, le=90),
    scans: ScanService = Depends(get_scan_service),
    db: Session = Depends(get_db),
) -> TrendResponse:
    return TrendResponse.model_validate(scans.trend(db, days=days))
