"""Scan history endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_scan_service
from app.schemas.analysis import AnalysisResponse
from app.schemas.history import ScanPage
from app.services.scan_service import ScanService

router = APIRouter(tags=["scans"])


@router.get("/scans", response_model=ScanPage, summary="List scan history")
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None, max_length=120),
    classification: Literal["safe", "suspicious", "phishing"] | None = None,
    scan_type: Literal["email", "url"] | None = None,
    scans: ScanService = Depends(get_scan_service),
    db: Session = Depends(get_db),
) -> ScanPage:
    payload = scans.list_scans(
        db,
        page=page,
        page_size=page_size,
        search=search,
        classification=classification,
        scan_type=scan_type,
    )
    return ScanPage.model_validate(payload)


@router.get("/scans/{scan_id}", response_model=AnalysisResponse, summary="Get a stored scan")
def get_scan(
    scan_id: int,
    scans: ScanService = Depends(get_scan_service),
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    result = scans.get(db, scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return AnalysisResponse.model_validate(result)
