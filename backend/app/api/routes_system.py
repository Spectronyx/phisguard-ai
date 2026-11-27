"""Health and model-status endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_registry
from app.core.config import Settings
from app.ml.model_registry import ModelRegistry
from app.schemas.history import ModelStatusResponse
from app.services.local_llm_service import LocalSemanticService

router = APIRouter(tags=["system"])


@router.get("/health", summary="Service health")
def health(
    request: Request,
    db: Session = Depends(get_db),
    registry: ModelRegistry = Depends(get_registry),
):
    settings: Settings = request.app.state.settings
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database = "error"

    status = registry.status()
    artifacts_ready = bool(status["email_available"] or status["url_available"])
    overall = "ok" if database == "ok" and artifacts_ready else "degraded"
    return {
        "status": overall,
        "version": settings.app_version,
        "database": database,
        "artifacts_ready": artifacts_ready,
        "llm_enabled": settings.any_llm_enabled,
        "local_llm_available": LocalSemanticService(settings).available,
        "timestamp": datetime.now(timezone.utc),
    }


@router.get("/models/status", response_model=ModelStatusResponse, summary="Model and module status")
def models_status(
    request: Request,
    registry: ModelRegistry = Depends(get_registry),
) -> ModelStatusResponse:
    settings: Settings = request.app.state.settings
    status = registry.status()
    local = LocalSemanticService(settings)
    local_artifact = None
    metrics_path = settings.artifacts_dir / "local_llm_metrics.json"
    if local.available and metrics_path.exists():
        local_meta = json.loads(metrics_path.read_text(encoding="utf-8"))
        local_artifact = {
            "name": "local_llm",
            "available": True,
            "path": str(settings.local_llm_dir),
            "algorithm": "distilbert-base-uncased (fine-tuned locally)",
            "trained_at": local_meta.get("generated_on"),
            "metrics": local_meta.get("test", {}).get("metrics", {}),
        }
    notes = [
        "Models are trained offline from public datasets; see backend/artifacts/metrics.json.",
        "Domain graph is NetworkX analytics, not a Graph Neural Network.",
    ]
    if not status["email_available"] or not status["url_available"]:
        notes.append(
            "One or more ML artifacts are missing: affected scans use the deterministic rules-only fallback."
        )
    if local.enabled:
        notes.append(
            "Local LLM: a DistilBERT text classifier fine-tuned on the phishing corpus runs on this machine; "
            "email text is never sent to an external provider."
        )
    elif settings.local_llm_enabled and not local.available:
        notes.append(
            "Local LLM artifacts are missing; build them with scripts/train_local_llm.py."
        )
    else:
        notes.append("Local LLM semantic analysis is disabled.")
    if settings.llm_configured:
        notes.append(
            "External LLM fallback is enabled: email content is sent to the configured provider when the local model is unavailable."
        )
    else:
        notes.append("External LLM fallback is disabled (no API key configured).")

    return ModelStatusResponse.model_validate({
        "email_model": status["email_model"],
        "url_model": status["url_model"],
        "domain_graph": status["domain_graph"],
        "inference_mode": status["inference_mode"],
        "llm_enabled": settings.any_llm_enabled,
        "llm_configured": settings.llm_configured,
        "llm_model": settings.llm_model,
        "local_llm": local_artifact,
        "local_llm_enabled": settings.local_llm_enabled,
        "local_llm_available": local.available,
        "local_llm_model": local.model_name,
        "llm_backend": "local_distilbert" if local.enabled else ("api" if settings.llm_configured else None),
        "notes": notes,
    })
