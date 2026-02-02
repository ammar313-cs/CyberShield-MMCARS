"""
Metrics Endpoints
System metrics and monitoring endpoints.
"""

from datetime import datetime
from fastapi import APIRouter, Request, HTTPException
import psutil
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("")
async def get_metrics(request: Request):
    """
    Get system metrics overview.

    Returns:
        System metrics
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    # System metrics
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    system_metrics = {
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_available_mb": memory.available / (1024 * 1024),
        "disk_percent": disk.percent,
    }

    # Security metrics
    security_metrics = {
        "active_threats": 0,
        "threats_detected_total": 0,
        "threats_mitigated_total": 0,
        "success_rate": 0.0,
    }

    if orchestrator:
        stats = orchestrator.get_agent_stats()
        orch_stats = stats.get("orchestrator", {})
        security_metrics.update({
            "active_threats": orch_stats.get("active_threats", 0),
            "threats_detected_total": orch_stats.get("orchestration_count", 0),
            "threats_mitigated_total": orch_stats.get("success_count", 0),
            "success_rate": orch_stats.get("success_rate", 0.0),
        })

    return {
        "system": system_metrics,
        "security": security_metrics,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/health")
async def get_health_metrics(request: Request):
    """
    Get detailed health metrics.

    Returns:
        Component health metrics
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    health = await orchestrator.check_system_health()

    return {
        "health": health.to_dict(),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/performance")
async def get_performance_metrics(request: Request):
    """
    Get performance metrics.

    Returns:
        Performance statistics
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    performance = {
        "avg_response_time_ms": 0.0,
        "avg_analysis_time_ms": 0.0,
        "avg_mitigation_time_ms": 0.0,
    }

    if orchestrator:
        stats = orchestrator.get_agent_stats()
        mitigator_stats = stats.get("mitigator", {})

        # Calculate performance from stats
        total_exec = mitigator_stats.get("execution_count", 0)
        if total_exec > 0:
            performance["avg_mitigation_time_ms"] = 10.0  # Would be calculated from actual data

    return {
        "performance": performance,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/threats/summary")
async def get_threat_summary(request: Request):
    """
    Get threat summary statistics.

    Returns:
        Threat statistics summary
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    summary = {
        "total_detected": 0,
        "total_mitigated": 0,
        "total_false_positives": 0,
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "by_type": {},
    }

    if orchestrator:
        stats = orchestrator.get_agent_stats()
        orch_stats = stats.get("orchestrator", {})
        summary["total_detected"] = orch_stats.get("orchestration_count", 0)
        summary["total_mitigated"] = orch_stats.get("success_count", 0)

    return {
        "summary": summary,
        "timestamp": datetime.utcnow().isoformat(),
    }
