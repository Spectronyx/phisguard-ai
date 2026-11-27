"""PhishGuard AI FastAPI application factory."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.agents.pipeline import AnalysisOrchestrator
from app.api.router import api_router
from app.core.config import PROJECT_ROOT, Settings, get_settings
from app.database.session import Base, build_engine, build_session_factory
from app.ml.model_registry import ModelRegistry
from app.services.scan_service import ScanService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("phishguard")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = build_engine(settings)
    session_factory = build_session_factory(engine)
    Base.metadata.create_all(engine)

    registry = ModelRegistry(settings)
    orchestrator = AnalysisOrchestrator(settings, registry=registry)
    scan_service = ScanService(settings)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Real-time phishing analysis for emails and URLs. Combines TF-IDF/Logistic "
            "Regression, lexical URL models, deterministic rules, domain-graph analytics and "
            "an optional LLM layer. Submitted URLs are never fetched."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.registry = registry
    app.state.orchestrator = orchestrator
    app.state.scan_service = scan_service

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )

    app.include_router(api_router, prefix=settings.api_prefix)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = []
        for error in exc.errors():
            errors.append({
                "field": ".".join(str(part) for part in error.get("loc", []) if part != "body"),
                "message": error.get("msg", "Invalid value"),
            })
        return JSONResponse(status_code=422, content={"detail": "Validation failed", "errors": errors})

    @app.exception_handler(HTTPException)
    async def http_handler(request: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    _mount_frontend(app)
    return app


def _mount_frontend(app: FastAPI) -> None:
    """Serve the built SPA when present (single-process demo deployment)."""
    dist = PROJECT_ROOT / "frontend" / "dist"
    index = dist / "index.html"
    if not index.exists():
        return

    assets = dist / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        if full_path.startswith(("api/", "docs", "redoc", "openapi.json")):
            raise HTTPException(status_code=404, detail="Not found")
        candidate = dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(index)


app = create_app()
