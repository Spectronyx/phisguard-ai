"""Analysis endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.agents.pipeline import AnalysisOrchestrator, AnalysisUnavailable
from app.api.deps import get_db, get_orchestrator, get_scan_service
from app.schemas.analysis import AnalysisResponse, EmailAnalysisRequest, UrlAnalysisRequest
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["analysis"])


@router.post("/analyze/email", response_model=AnalysisResponse, summary="Analyse an email")
def analyze_email(
    payload: EmailAnalysisRequest,
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    scans: ScanService = Depends(get_scan_service),
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    try:
        result = orchestrator.analyze_email(
            subject=payload.subject,
            body=payload.body,
            sender=payload.sender,
            urls=payload.urls,
        )
    except AnalysisUnavailable as exc:
        raise HTTPException(status_code=503, detail="Analysis could not be completed with available modules.") from exc
    except Exception as exc:
        logger.exception("Email analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed unexpectedly.") from exc

    scan = scans.create(db, result)
    result["scan_id"] = scan.id
    return AnalysisResponse.model_validate(result)


@router.post("/analyze/url", response_model=AnalysisResponse, summary="Analyse a URL")
def analyze_url(
    payload: UrlAnalysisRequest,
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    scans: ScanService = Depends(get_scan_service),
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    try:
        result = orchestrator.analyze_url(payload.url)
    except AnalysisUnavailable as exc:
        raise HTTPException(status_code=503, detail="Analysis could not be completed with available modules.") from exc
    except Exception as exc:
        logger.exception("URL analysis failed")
        raise HTTPException(status_code=500, detail="Analysis failed unexpectedly.") from exc

    scan = scans.create(db, result)
    result["scan_id"] = scan.id
    return AnalysisResponse.model_validate(result)
