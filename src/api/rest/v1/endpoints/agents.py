"""
Agents Endpoints
Agent status and management endpoints.
"""

from datetime import datetime
from fastapi import APIRouter, Request, HTTPException
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("")
async def list_agents(request: Request):
    """
    List all agents and their status.

    Returns:
        List of agents with status
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    agents = [
        {
            "id": orchestrator.analyzer.bot_id,
            "type": "analyzer",
            "status": orchestrator.analyzer.get_health_status(),
            "stats": orchestrator.analyzer.get_stats(),
        },
        {
            "id": orchestrator.responder.bot_id,
            "type": "responder",
            "status": orchestrator.responder.get_health_status(),
            "stats": orchestrator.responder.get_stats(),
        },
        {
            "id": orchestrator.mitigator.bot_id,
            "type": "mitigator",
            "status": orchestrator.mitigator.get_health_status(),
            "stats": orchestrator.mitigator.get_stats(),
        },
        {
            "id": orchestrator.reporter.bot_id,
            "type": "reporter",
            "status": orchestrator.reporter.get_health_status(),
            "stats": orchestrator.reporter.get_stats(),
        },
        {
            "id": orchestrator.monitor.bot_id,
            "type": "monitor",
            "status": orchestrator.monitor.get_health_status(),
            "stats": orchestrator.monitor.get_stats(),
        },
    ]

    return {
        "agents": agents,
        "count": len(agents),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/stats")
async def get_agent_stats(request: Request):
    """
    Get comprehensive agent statistics.

    Returns:
        Detailed statistics for all agents
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    stats = orchestrator.get_agent_stats()

    return {
        "stats": stats,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/{agent_id}")
async def get_agent(
    request: Request,
    agent_id: str,
):
    """
    Get specific agent by ID.

    Args:
        agent_id: Agent identifier

    Returns:
        Agent details
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    # Find agent by ID
    agents = {
        orchestrator.analyzer.bot_id: orchestrator.analyzer,
        orchestrator.responder.bot_id: orchestrator.responder,
        orchestrator.mitigator.bot_id: orchestrator.mitigator,
        orchestrator.reporter.bot_id: orchestrator.reporter,
        orchestrator.monitor.bot_id: orchestrator.monitor,
    }

    agent = agents.get(agent_id)

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return {
        "id": agent.bot_id,
        "type": agent.bot_type,
        "status": agent.get_health_status(),
        "stats": agent.get_stats(),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/alerts/recent")
async def get_recent_alerts(request: Request):
    """
    Get recent security alerts.

    Returns:
        Recent alerts from reporter bot
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    alerts = orchestrator.reporter.get_recent_alerts(10)

    return {
        "alerts": [a.to_dict() for a in alerts],
        "count": len(alerts),
        "timestamp": datetime.utcnow().isoformat(),
    }
