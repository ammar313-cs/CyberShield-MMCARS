"""
Health Check Endpoints
System health and status endpoints.
"""

from datetime import datetime
from fastapi import APIRouter, Request
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("")
async def health_check():
    """
    Basic health check endpoint.

    Returns:
        Health status
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "cybershield-api",
    }


@router.get("/detailed")
async def detailed_health(request: Request):
    """
    Detailed health check with component status.

    Returns:
        Detailed health information
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    components = {
        "api": "healthy",
        "orchestrator": "unknown",
        "redis": "unknown",
    }

    if orchestrator:
        try:
            health_status = await orchestrator.check_system_health()
            components["orchestrator"] = health_status.overall
            components.update(health_status.components)
        except Exception as e:
            logger.error("health_check_failed", error=str(e))
            components["orchestrator"] = "unhealthy"

    overall = "healthy"
    if any(v in ("critical", "unhealthy") for v in components.values()):
        overall = "critical"
    elif any(v == "degraded" for v in components.values()):
        overall = "degraded"

    return {
        "status": overall,
        "timestamp": datetime.utcnow().isoformat(),
        "service": "cybershield-api",
        "version": "0.1.0",
        "components": components,
    }


@router.get("/ready")
async def readiness_check(request: Request):
    """
    Kubernetes readiness probe endpoint.

    Returns:
        Readiness status
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    ready = orchestrator is not None and orchestrator._is_running

    return {
        "ready": ready,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/live")
async def liveness_check():
    """
    Kubernetes liveness probe endpoint.

    Returns:
        Liveness status
    """
    return {
        "alive": True,
        "timestamp": datetime.utcnow().isoformat(),
    }
