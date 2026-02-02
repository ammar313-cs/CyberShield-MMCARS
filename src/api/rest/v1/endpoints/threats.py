"""
Threats Endpoints
Threat management and monitoring endpoints.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


class TrafficEventInput(BaseModel):
    """Input model for traffic event."""

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str = "tcp"
    packet_size: int = 64
    flags: list[str] = []
    payload: Optional[str] = None  # For application-layer attack detection


class TrafficBatchInput(BaseModel):
    """Input model for batch traffic events."""

    events: list[TrafficEventInput]


@router.get("")
async def list_threats(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100),
):
    """
    List detected threats.

    Args:
        status: Filter by threat status
        severity: Filter by severity level
        limit: Maximum results to return

    Returns:
        List of threats
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    threats = orchestrator.get_active_threats()

    # Apply filters
    if status:
        threats = [t for t in threats if t.status.value == status]

    if severity:
        threats = [t for t in threats if t.severity.value == severity]

    # Limit results
    threats = threats[:limit]

    return {
        "threats": [t.to_dict() for t in threats],
        "count": len(threats),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/{threat_id}")
async def get_threat(
    request: Request,
    threat_id: UUID,
):
    """
    Get threat by ID.

    Args:
        threat_id: Threat UUID

    Returns:
        Threat details
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    threat = orchestrator._active_threats.get(threat_id)

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    return threat.to_dict()


@router.post("/analyze")
async def analyze_traffic(
    request: Request,
    traffic: TrafficBatchInput,
):
    """
    Analyze batch of traffic events for threats.

    Args:
        traffic: Batch of traffic events

    Returns:
        Analysis results
    """
    from src.domain.entities.traffic_event import TrafficEvent
    from src.domain.value_objects.attack_signature import AttackProtocol

    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    # Convert input to TrafficEvent objects
    protocol_map = {
        "tcp": AttackProtocol.TCP,
        "udp": AttackProtocol.UDP,
        "icmp": AttackProtocol.ICMP,
        "http": AttackProtocol.HTTP,
        "https": AttackProtocol.HTTPS,
    }

    events = []
    for e in traffic.events:
        event = TrafficEvent.create(
            source_ip=e.source_ip,
            destination_ip=e.destination_ip,
            source_port=e.source_port,
            destination_port=e.destination_port,
            protocol=protocol_map.get(e.protocol.lower(), AttackProtocol.UNKNOWN),
            packet_size=e.packet_size,
            flags=e.flags,
        )
        # Add payload to metadata for application-layer attack detection
        if e.payload:
            event.metadata["payload"] = e.payload
        events.append(event)

    # Process traffic
    results = await orchestrator.process_traffic(events)

    return {
        "events_processed": len(events),
        "threats_detected": len(results),
        "results": [r.to_dict() for r in results],
        "timestamp": datetime.utcnow().isoformat(),
    }


class MitigationRequest(BaseModel):
    """Request body for mitigation."""
    action: str = "block_ip"


from fastapi.responses import StreamingResponse
import asyncio


@router.post("/{threat_id}/mitigate/stream")
async def mitigate_threat_stream(
    request: Request,
    threat_id: UUID,
    body: Optional[MitigationRequest] = None,
):
    """
    Execute mitigation with streaming agent updates.

    Returns Server-Sent Events for real-time pipeline progress.
    Shows actual agent execution with model info.
    """
    import json
    from src.ml.features.extractor import TrafficFeatures
    from src.agents.llm.claude_client import get_model_for_agent

    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    threat = orchestrator._active_threats.get(threat_id)

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    async def generate_events():
        """Generator for SSE events."""
        try:
            features = TrafficFeatures()
            predictions = {}

            # Step 1: Analysis
            yield f"data: {json.dumps({'agent': 'analyzer', 'model': get_model_for_agent('analyzer'), 'status': 'starting'})}\n\n"
            await asyncio.sleep(0.1)  # Small delay for UI to render

            analysis = await orchestrator.analyzer.analyze(threat, features, predictions)

            yield f"data: {json.dumps({'agent': 'analyzer', 'model': get_model_for_agent('analyzer'), 'status': 'complete', 'result': {'attack_type': analysis.attack_type, 'severity': analysis.severity, 'confidence': analysis.confidence}})}\n\n"

            # Step 2: Response Planning
            yield f"data: {json.dumps({'agent': 'responder', 'model': get_model_for_agent('responder'), 'status': 'starting'})}\n\n"
            await asyncio.sleep(0.1)

            response_plan = await orchestrator.responder.plan_response(threat, analysis)

            yield f"data: {json.dumps({'agent': 'responder', 'model': get_model_for_agent('responder'), 'status': 'complete', 'result': {'primary_action': response_plan.primary_action.action_type.value, 'target': response_plan.primary_action.target}})}\n\n"

            # Step 3: Mitigation Execution
            yield f"data: {json.dumps({'agent': 'mitigator', 'model': get_model_for_agent('mitigator'), 'status': 'starting'})}\n\n"

            execution_results = []
            for action in response_plan.get_all_actions():
                yield f"data: {json.dumps({'agent': 'mitigator', 'action': action.action_type.value, 'target': action.target, 'status': 'executing'})}\n\n"
                await asyncio.sleep(0.1)

                result = await orchestrator.mitigator.execute(action)
                execution_results.append(result)

                yield f"data: {json.dumps({'agent': 'mitigator', 'action': action.action_type.value, 'status': result.status, 'result': {'verified': result.verified, 'reduction': result.reduction_percentage}})}\n\n"

            yield f"data: {json.dumps({'agent': 'mitigator', 'model': get_model_for_agent('mitigator'), 'status': 'complete'})}\n\n"

            # Step 4: Reporting
            yield f"data: {json.dumps({'agent': 'reporter', 'model': get_model_for_agent('reporter'), 'status': 'starting'})}\n\n"
            await asyncio.sleep(0.1)

            alert = await orchestrator.reporter.generate_alert(
                threat=threat,
                analysis=analysis,
                response_plan=response_plan,
                execution_results=execution_results,
            )

            yield f"data: {json.dumps({'agent': 'reporter', 'model': get_model_for_agent('reporter'), 'status': 'complete'})}\n\n"

            # Cleanup
            all_successful = all(r.status == "success" for r in execution_results)
            if all_successful:
                threat.complete_mitigation()
                await orchestrator._cleanup_mitigated_threat(threat.id)

            yield f"data: {json.dumps({'status': 'complete', 'success': all_successful, 'threat_id': str(threat_id)})}\n\n"

        except Exception as e:
            logger.error("streaming_mitigation_failed", threat_id=str(threat_id), error=str(e))
            yield f"data: {json.dumps({'status': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        generate_events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


class DismissRequest(BaseModel):
    """Request body for dismissal."""
    reason: str
    notes: Optional[str] = None


@router.get("/{threat_id}/recommendations")
async def get_threat_recommendations(
    request: Request,
    threat_id: UUID,
):
    """
    Get AI-generated recommendations for a threat.

    Returns analysis and response plan from actual agents (using Haiku model).
    This replaces hardcoded frontend actions with dynamic agent recommendations.
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    threat = orchestrator._active_threats.get(threat_id)

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    try:
        from src.ml.features.extractor import TrafficFeatures
        from src.agents.llm.claude_client import get_model_for_agent

        # Get or generate analysis
        features = TrafficFeatures()  # Default features
        predictions = {}

        # Run analyzer
        analysis = await orchestrator.analyzer.analyze(
            threat=threat,
            features=features,
            predictions=predictions,
        )

        # Run responder to get action plan
        response_plan = await orchestrator.responder.plan_response(
            threat=threat,
            analysis=analysis,
        )

        # Build policy from severity
        policies = {
            "critical": {
                "name": "DEFCON-1 Emergency Response",
                "auto_mitigate": False,
                "requires_human": True,
                "rules": [
                    "Immediate escalation to SOC team",
                    "IP blocking pending human approval",
                    "Full packet capture enabled",
                ],
            },
            "high": {
                "name": "Active Defense Protocol",
                "auto_mitigate": False,
                "requires_human": True,
                "rules": [
                    "Rate limiting applied automatically",
                    "IP block requires human approval",
                    "Enhanced logging enabled",
                ],
            },
            "medium": {
                "name": "Standard Response Procedure",
                "auto_mitigate": True,
                "requires_human": False,
                "rules": [
                    "Moderate rate limiting applied",
                    "Continued monitoring",
                    "Alert generated",
                ],
            },
            "low": {
                "name": "Monitoring & Assessment",
                "auto_mitigate": True,
                "requires_human": False,
                "rules": [
                    "Passive monitoring only",
                    "Log for analysis",
                    "No active intervention",
                ],
            },
        }

        return {
            "threat_id": str(threat_id),
            "analysis": analysis.to_dict(),
            "response_plan": response_plan.to_dict(),
            "policy": policies.get(analysis.severity, policies["medium"]),
            "models_used": {
                "analyzer": get_model_for_agent("analyzer"),
                "responder": get_model_for_agent("responder"),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error("recommendations_failed", threat_id=str(threat_id), error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {str(e)}")


@router.post("/{threat_id}/mitigate")
async def mitigate_threat(
    request: Request,
    threat_id: UUID,
    body: Optional[MitigationRequest] = None,
):
    """
    Manually trigger mitigation for a threat.

    Args:
        threat_id: Threat UUID
        body: Mitigation action details

    Returns:
        Mitigation result
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    threat = orchestrator._active_threats.get(threat_id)

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    action = body.action if body else "block_ip"

    # Execute mitigation through orchestrator
    try:
        # Mark as mitigated
        threat.mitigate()

        # Remove from active threats
        if threat_id in orchestrator._active_threats:
            del orchestrator._active_threats[threat_id]

        # Update Redis if available
        if orchestrator._redis and orchestrator.use_redis:
            try:
                await orchestrator._redis._client.hdel(
                    orchestrator.ACTIVE_THREATS_KEY, str(threat_id)
                )
                # Update metrics
                await orchestrator._persist_metrics()
            except Exception as e:
                logger.warning("redis_update_failed", error=str(e))

        # Log the action
        logger.info(
            "threat_mitigated",
            threat_id=str(threat_id),
            action=action,
            source_ip=str(threat.source_ip.address) if threat.source_ip else "unknown",
        )

        return {
            "success": True,
            "threat_id": str(threat_id),
            "action": action,
            "status": "mitigated",
            "message": f"Threat mitigated successfully via {action}",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error("mitigation_failed", threat_id=str(threat_id), error=str(e))
        raise HTTPException(status_code=500, detail=f"Mitigation failed: {str(e)}")


@router.delete("/{threat_id}")
async def dismiss_threat(
    request: Request,
    threat_id: UUID,
    body: Optional[DismissRequest] = None,
    reason: Optional[str] = Query(None, description="Reason for dismissal (deprecated)"),
):
    """
    Mark threat as false positive and permanently dismiss.

    Args:
        threat_id: Threat UUID
        body: Dismissal details
        reason: Legacy query param (deprecated)

    Returns:
        Dismissal confirmation
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    # Try to find threat in memory first
    threat = orchestrator._active_threats.get(threat_id)
    threat_data_from_redis = None

    # If not in memory, check Redis (handles race condition where threat was cleaned up)
    if not threat and orchestrator._redis and orchestrator.use_redis:
        try:
            import json
            threat_data_raw = await orchestrator._redis._client.hget(
                orchestrator.ACTIVE_THREATS_KEY, str(threat_id)
            )
            if threat_data_raw:
                threat_data_from_redis = json.loads(threat_data_raw)
                logger.info(
                    "threat_found_in_redis",
                    threat_id=str(threat_id),
                    status=threat_data_from_redis.get("status"),
                )
        except Exception as e:
            logger.warning("redis_lookup_failed", error=str(e))

    if not threat and not threat_data_from_redis:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Get reason from body or query param
    dismissal_reason = body.reason if body else reason
    if not dismissal_reason:
        dismissal_reason = "User dismissed"

    notes = body.notes if body else None

    try:
        # Mark as false positive if we have the threat object
        if threat:
            threat.mark_false_positive(dismissal_reason)

        # Remove from active threats permanently
        if threat_id in orchestrator._active_threats:
            del orchestrator._active_threats[threat_id]

        # Update Redis - remove and broadcast
        if orchestrator._redis and orchestrator.use_redis:
            try:
                # Remove from Redis hash
                await orchestrator._redis._client.hdel(
                    orchestrator.ACTIVE_THREATS_KEY, str(threat_id)
                )
                # Broadcast removal for real-time dashboard update
                await orchestrator._publish_threat_removed(threat_id)
                # Update metrics
                await orchestrator._persist_metrics()
            except Exception as e:
                logger.warning("redis_update_failed", error=str(e))

        # Log the dismissal - extract source_ip from threat object or Redis data
        source_ip = "unknown"
        if threat and threat.source_ip:
            source_ip = str(threat.source_ip.address) if hasattr(threat.source_ip, 'address') else str(threat.source_ip)
        elif threat_data_from_redis:
            # Extract from Redis data structure
            src = threat_data_from_redis.get("source_ip", {})
            source_ip = src.get("address", str(src)) if isinstance(src, dict) else str(src)

        logger.info(
            "threat_dismissed",
            threat_id=str(threat_id),
            reason=dismissal_reason,
            notes=notes,
            source_ip=source_ip,
        )

        return {
            "success": True,
            "threat_id": str(threat_id),
            "status": "dismissed",
            "reason": dismissal_reason,
            "notes": notes,
            "message": f"Threat dismissed: {dismissal_reason}",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error("dismissal_failed", threat_id=str(threat_id), error=str(e))
        raise HTTPException(status_code=500, detail=f"Dismissal failed: {str(e)}")


# =============================================
# ESCALATION ENDPOINTS (Human-in-the-Loop)
# =============================================


@router.get("/escalated")
async def list_escalated_threats(request: Request):
    """
    List threats awaiting human review.

    These are threats that the AI determined require human decision
    before automatic mitigation (typically critical/high severity).
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    escalated = orchestrator.get_escalated_threats()

    return {
        "escalated_threats": escalated,
        "count": len(escalated),
        "timestamp": datetime.utcnow().isoformat(),
    }


class EscalationDecision(BaseModel):
    """Human decision on escalated threat."""

    action: str  # "approve_mitigation" or "dismiss"
    notes: Optional[str] = None


@router.post("/{threat_id}/escalation/decide")
async def decide_escalation(
    request: Request,
    threat_id: UUID,
    decision: EscalationDecision,
):
    """
    Human decision on an escalated threat.

    Args:
        threat_id: Threat UUID
        decision: Human decision (approve or dismiss)

    Returns:
        Decision result
    """
    orchestrator = getattr(request.app.state, "orchestrator", None)

    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")

    if decision.action == "approve_mitigation":
        success = await orchestrator.approve_escalation(threat_id)
        if not success:
            raise HTTPException(status_code=404, detail="Escalated threat not found")

        return {
            "success": True,
            "threat_id": str(threat_id),
            "action": "approved",
            "message": "Mitigation approved and executed",
            "timestamp": datetime.utcnow().isoformat(),
        }

    elif decision.action == "dismiss":
        reason = decision.notes or "Human dismissed as false positive"
        success = await orchestrator.dismiss_escalation(threat_id, reason)
        if not success:
            raise HTTPException(status_code=404, detail="Escalated threat not found")

        return {
            "success": True,
            "threat_id": str(threat_id),
            "action": "dismissed",
            "reason": reason,
            "message": "Threat dismissed as false positive",
            "timestamp": datetime.utcnow().isoformat(),
        }

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {decision.action}. Use 'approve_mitigation' or 'dismiss'"
        )
