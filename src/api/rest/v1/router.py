"""
API V1 Router
Main router for API version 1.
"""

from fastapi import APIRouter

from src.api.rest.v1.endpoints import health, threats, agents, metrics

api_router = APIRouter()

# Include endpoint routers
api_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health"],
)

api_router.include_router(
    threats.router,
    prefix="/threats",
    tags=["Threats"],
)

api_router.include_router(
    agents.router,
    prefix="/agents",
    tags=["Agents"],
)

api_router.include_router(
    metrics.router,
    prefix="/metrics",
    tags=["Metrics"],
)
