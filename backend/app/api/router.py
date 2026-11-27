"""API router aggregation."""

from fastapi import APIRouter

from app.api import routes_analysis, routes_dashboard, routes_scans, routes_system

api_router = APIRouter()
api_router.include_router(routes_analysis.router)
api_router.include_router(routes_scans.router)
api_router.include_router(routes_dashboard.router)
api_router.include_router(routes_system.router)
