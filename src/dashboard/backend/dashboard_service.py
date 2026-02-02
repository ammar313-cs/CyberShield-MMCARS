"""
Dashboard Backend Service
WebSocket-enabled dashboard server for real-time monitoring.
"""

import asyncio
import json
from datetime import datetime
from typing import Set
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
import structlog

from src.infrastructure.persistence.redis_client import RedisClient, get_redis_client
from src.infrastructure.health.health_checker import HealthChecker, HEALTH_COMPONENTS_KEY
from src.infrastructure.health.heartbeat import HeartbeatManager, HEALTH_AGENTS_KEY
from src.agents.coordinator.orchestrator import AgentOrchestrator
from src.api.rest.security import verify_api_key
from src.api.rest.middleware.auth import APIKeyMiddleware

logger = structlog.get_logger(__name__)

# Dashboard paths
DASHBOARD_DIR = Path(__file__).parent.parent / "frontend"
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and track new connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("websocket_connected", count=len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove disconnected client."""
        self.active_connections.discard(websocket)
        logger.info("websocket_disconnected", count=len(self.active_connections))

    async def broadcast(self, message: dict) -> None:
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return

        message_str = json.dumps(message)
        disconnected = set()

        for connection in self.active_connections:
            try:
                await connection.send_text(message_str)
            except Exception:
                disconnected.add(connection)

        # Clean up disconnected
        for conn in disconnected:
            self.active_connections.discard(conn)


class DashboardService:
    """
    Dashboard service with WebSocket real-time updates.

    Provides:
    - Real-time threat monitoring
    - Agent status updates
    - System metrics visualization
    - Alert notifications
    """

    def __init__(
        self,
        host: str = None,
        port: int = None,
    ):
        import os
        self.host = host or os.getenv("DASHBOARD_HOST", "0.0.0.0")
        self.port = port or int(os.getenv("DASHBOARD_PORT", "8081"))
        self.manager = ConnectionManager()
        self._is_running = False
        self._redis: RedisClient = None
        self._orchestrator: AgentOrchestrator = None
        self._health_checker: HealthChecker = None
        self._heartbeat_manager: HeartbeatManager = None

        # Create FastAPI app
        self.app = self._create_app()

    def _create_app(self) -> FastAPI:
        """Create the dashboard FastAPI application."""
        app = FastAPI(
            title="CyberShield Dashboard",
            description="Real-time Security Monitoring Dashboard",
            version="0.1.0",
        )

        # Add API Key authentication middleware
        # Exclude static files and the dashboard page itself
        app.add_middleware(
            APIKeyMiddleware,
            exclude_paths=["/static", "/", "/ws"],  # Allow static files, dashboard page, and WebSocket (auth handled separately)
        )

        # Mount static files
        if STATIC_DIR.exists():
            app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        # Templates
        templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

        @app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Serve the dashboard HTML."""
            return templates.TemplateResponse(
                "index.html",
                {
                    "request": request,
                    "title": "CyberShield Dashboard",
                },
            )

        @app.get("/about", response_class=HTMLResponse)
        async def about(request: Request):
            """Serve the about page."""
            return templates.TemplateResponse(
                "about.html",
                {
                    "request": request,
                    "title": "About CyberShield",
                },
            )

        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates."""
            # Authenticate WebSocket connection
            api_key = websocket.query_params.get("api_key")
            if not api_key:
                # Starlette headers are lowercase
                api_key = websocket.headers.get("x-api-key")

            if not api_key or not verify_api_key(api_key):
                logger.warning(
                    "websocket_auth_failed",
                    client=websocket.client.host if websocket.client else "unknown",
                )
                await websocket.close(code=4001, reason="Unauthorized: Invalid or missing API key")
                return

            await self.manager.connect(websocket)

            try:
                # Send initial state
                await self._send_initial_state(websocket)

                # Keep connection alive
                while True:
                    # Wait for messages from client
                    data = await websocket.receive_text()
                    message = json.loads(data)

                    # Handle client messages
                    await self._handle_client_message(websocket, message)

            except WebSocketDisconnect:
                self.manager.disconnect(websocket)
            except Exception as e:
                logger.error("websocket_error", error=str(e))
                self.manager.disconnect(websocket)

        @app.get("/api/status")
        async def get_status():
            """Get current system status."""
            return await self._get_system_status()

        @app.get("/api/threats")
        async def get_threats():
            """Get active threats (excludes mitigated and false positives)."""
            # Try to get threats from Redis first (shared with API)
            if self._redis:
                try:
                    threats_data = await self._redis._client.hgetall("cybershield:active_threats")
                    if threats_data:
                        all_threats = [json.loads(v) for v in threats_data.values()]
                        # Filter to only show truly active threats
                        threats = [
                            t for t in all_threats
                            if t.get("status") not in ("mitigated", "false_positive")
                        ]
                        return {"threats": threats, "count": len(threats)}
                except Exception as e:
                    logger.warning("failed_to_get_redis_threats", error=str(e))

            # Fallback to orchestrator (already filters by is_active)
            if not self._orchestrator:
                return {"threats": [], "count": 0}

            threats = self._orchestrator.get_active_threats()
            return {
                "threats": [t.to_dict() for t in threats],
                "count": len(threats),
            }

        @app.get("/api/alerts")
        async def get_alerts():
            """Get recent alerts (persisted in Redis)."""
            if not self._orchestrator:
                return {"alerts": [], "count": 0}

            # Try to get persisted alerts from Redis first
            try:
                alerts = await self._orchestrator.reporter.get_persisted_alerts(20)
                if alerts:
                    return {"alerts": alerts, "count": len(alerts)}
            except Exception as e:
                logger.warning("failed_to_get_persisted_alerts", error=str(e))

            # Fallback to in-memory alerts
            alerts = self._orchestrator.reporter.get_recent_alerts(20)
            return {
                "alerts": [a.to_dict() for a in alerts],
                "count": len(alerts),
            }

        return app

    async def _send_initial_state(self, websocket: WebSocket) -> None:
        """Send initial dashboard state to new connection."""
        status = await self._get_system_status()

        # Include persisted alerts
        alerts = []
        if self._orchestrator:
            try:
                alerts = await self._orchestrator.reporter.get_persisted_alerts(20)
            except Exception:
                alerts = [a.to_dict() for a in self._orchestrator.reporter.get_recent_alerts(20)]

        status["alerts"] = alerts

        # Include only active threats from Redis (filter out mitigated/false_positive)
        threats = []
        if self._redis:
            try:
                threats_data = await self._redis._client.hgetall("cybershield:active_threats")
                if threats_data:
                    all_threats = [json.loads(v) for v in threats_data.values()]
                    # Filter to only show truly active threats
                    threats = [
                        t for t in all_threats
                        if t.get("status") not in ("mitigated", "false_positive")
                    ]
            except Exception as e:
                logger.warning("failed_to_get_initial_threats", error=str(e))

        status["threats"] = threats

        # Include agent actions history
        agent_actions = []
        if self._orchestrator:
            try:
                agent_actions = await self._orchestrator.get_agent_actions(50)
            except Exception as e:
                logger.warning("failed_to_get_agent_actions", error=str(e))

        status["agent_actions"] = agent_actions

        await websocket.send_text(json.dumps({
            "type": "initial_state",
            "data": status,
            "timestamp": datetime.utcnow().isoformat(),
        }))

    async def _handle_client_message(
        self,
        websocket: WebSocket,
        message: dict,
    ) -> None:
        """Handle messages from client."""
        msg_type = message.get("type")

        if msg_type == "ping":
            await websocket.send_text(json.dumps({
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat(),
            }))

        elif msg_type == "subscribe":
            # Handle subscription to specific channels
            channels = message.get("channels", [])
            logger.debug("client_subscribed", channels=channels)

        elif msg_type == "get_status":
            status = await self._get_system_status()
            await websocket.send_text(json.dumps({
                "type": "status_update",
                "data": status,
                "timestamp": datetime.utcnow().isoformat(),
            }))

    async def _get_system_status(self) -> dict:
        """Get comprehensive system status."""
        status = {
            "overall": "healthy",
            "components": {},
            "metrics": {
                "threats_active": 0,
                "threats_detected_total": 0,
                "threats_mitigated_total": 0,
                "success_rate": 0.0,
            },
            "agents": [],
        }

        # Try to get metrics from Redis first (shared with API)
        if self._redis:
            try:
                metrics_data = await self._redis._client.get("cybershield:metrics")
                if metrics_data:
                    redis_metrics = json.loads(metrics_data)
                    status["metrics"]["threats_detected_total"] = redis_metrics.get("threats_detected_total", 0)
                    status["metrics"]["threats_mitigated_total"] = redis_metrics.get("threats_mitigated_total", 0)
                    status["metrics"]["threats_active"] = redis_metrics.get("active_threats", 0)
                    status["metrics"]["success_rate"] = redis_metrics.get("success_rate", 0.0)
            except Exception as e:
                logger.warning("failed_to_get_redis_metrics", error=str(e))

        # Step 1: Try to get component health from Redis (real health checks)
        components_from_redis = await self._get_component_health_from_redis()
        if components_from_redis:
            status["components"] = components_from_redis
            # Determine overall status from components
            status["overall"] = self._calculate_overall_status(components_from_redis)
            logger.debug("component_health_from_redis", components=components_from_redis)

        # Step 2: Try to get agent health from Redis
        agents_from_redis = await self._get_agent_health_from_redis()

        if self._orchestrator:
            # If we didn't get component health from Redis, fall back to orchestrator
            if not components_from_redis:
                health = await self._orchestrator.check_system_health()
                status["overall"] = health.overall
                status["components"] = health.components

            # Only use orchestrator metrics if Redis metrics are empty
            if status["metrics"]["threats_detected_total"] == 0:
                health = await self._orchestrator.check_system_health()
                # Don't override metrics if already populated
                pass

            # Get agent stats - merge with Redis health data
            agent_stats = self._orchestrator.get_agent_stats()
            status["agents"] = [
                {
                    "type": "orchestrator",
                    "stats": agent_stats.get("orchestrator", {}),
                    "status": agents_from_redis.get("orchestrator", {}).get("status", "active"),
                },
                {
                    "type": "analyzer",
                    "stats": agent_stats.get("analyzer", {}),
                    "status": agents_from_redis.get("analyzer_001", {}).get("status")
                    or agent_stats.get("analyzer", {}).get("health_status", "active"),
                },
                {
                    "type": "responder",
                    "stats": agent_stats.get("responder", {}),
                    "status": agents_from_redis.get("responder_001", {}).get("status")
                    or agent_stats.get("responder", {}).get("health_status", "active"),
                },
                {
                    "type": "mitigator",
                    "stats": agent_stats.get("mitigator", {}),
                    "status": agents_from_redis.get("mitigator_001", {}).get("status")
                    or agent_stats.get("mitigator", {}).get("health_status", "active"),
                },
                {
                    "type": "reporter",
                    "stats": agent_stats.get("reporter", {}),
                    "status": agents_from_redis.get("reporter_001", {}).get("status")
                    or agent_stats.get("reporter", {}).get("health_status", "active"),
                },
                {
                    "type": "monitor",
                    "stats": agent_stats.get("monitor", {}),
                    "status": agents_from_redis.get("monitor_001", {}).get("status")
                    or agent_stats.get("monitor", {}).get("health_status", "active"),
                },
            ]

        return status

    async def _get_component_health_from_redis(self) -> dict[str, str]:
        """
        Get component health status from Redis.

        Returns:
            Dict mapping component name to status string
        """
        if not self._redis or not self._redis._client:
            return {}

        try:
            health_data = await self._redis._client.hgetall(HEALTH_COMPONENTS_KEY)
            if not health_data:
                return {}

            components = {}
            for name, data_str in health_data.items():
                data = json.loads(data_str)
                # Convert HealthStatus value to simple status string
                status = data.get("status", "unknown")
                if status == "healthy":
                    components[name] = "healthy"
                elif status == "degraded":
                    components[name] = "degraded"
                else:
                    components[name] = "critical"

            return components

        except Exception as e:
            logger.warning("failed_to_get_component_health_from_redis", error=str(e))
            return {}

    async def _get_agent_health_from_redis(self) -> dict[str, dict]:
        """
        Get agent health status from Redis.

        Returns:
            Dict mapping agent_id to health data
        """
        if not self._redis or not self._redis._client:
            return {}

        try:
            health_data = await self._redis._client.hgetall(HEALTH_AGENTS_KEY)
            if not health_data:
                return {}

            return {
                agent_id: json.loads(data) for agent_id, data in health_data.items()
            }

        except Exception as e:
            logger.warning("failed_to_get_agent_health_from_redis", error=str(e))
            return {}

    def _calculate_overall_status(self, components: dict[str, str]) -> str:
        """
        Calculate overall system status from component statuses.

        Args:
            components: Dict mapping component name to status

        Returns:
            Overall status: "healthy", "degraded", or "critical"
        """
        if not components:
            return "healthy"

        critical_count = sum(1 for s in components.values() if s == "critical")
        degraded_count = sum(1 for s in components.values() if s == "degraded")

        if critical_count >= 2:
            return "critical"
        elif critical_count >= 1 or degraded_count >= 2:
            return "degraded"
        else:
            return "healthy"

    async def broadcast_update(self, update_type: str, data: dict) -> None:
        """Broadcast update to all connected clients."""
        await self.manager.broadcast({
            "type": update_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def start_background_tasks(self) -> None:
        """Start background tasks for updates."""
        asyncio.create_task(self._periodic_status_update())
        asyncio.create_task(self._subscribe_to_events())

    async def _periodic_status_update(self) -> None:
        """Periodically send status updates."""
        while self._is_running:
            try:
                status = await self._get_system_status()
                await self.manager.broadcast({
                    "type": "status_update",
                    "data": status,
                    "timestamp": datetime.utcnow().isoformat(),
                })
            except Exception as e:
                logger.error("status_update_failed", error=str(e))

            await asyncio.sleep(5)  # Update every 5 seconds

    async def _subscribe_to_events(self) -> None:
        """Subscribe to Redis pub/sub for real-time events."""
        if not self._redis:
            return

        try:
            pubsub = await self._redis.psubscribe("cybershield:*")

            async for message in pubsub.listen():
                if message["type"] == "pmessage":
                    channel = message["channel"]
                    data = json.loads(message["data"])

                    if "alerts" in channel:
                        await self.manager.broadcast({
                            "type": "alert",
                            "data": data,
                            "timestamp": datetime.utcnow().isoformat(),
                        })
                    elif "threats" in channel:
                        # Check if this is a threat removal event
                        if data.get("action") == "removed":
                            await self.manager.broadcast({
                                "type": "threat_removed",
                                "data": {"threat_id": data.get("id")},
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                        else:
                            await self.manager.broadcast({
                                "type": "threat",
                                "data": data,
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                    elif "events" in channel:
                        # Check if this is an agent action event
                        if data.get("type") == "agent_action":
                            await self.manager.broadcast({
                                "type": "agent_action",
                                "data": data,
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                        else:
                            await self.manager.broadcast({
                                "type": "event",
                                "data": data,
                                "timestamp": datetime.utcnow().isoformat(),
                            })

        except Exception as e:
            logger.error("event_subscription_failed", error=str(e))


# Create dashboard service
dashboard_service = DashboardService()


async def main():
    """Main entry point for dashboard service."""
    import uvicorn

    logger.info("starting_dashboard_service")

    # Initialize Redis
    try:
        dashboard_service._redis = get_redis_client()
        await dashboard_service._redis.connect()
    except Exception as e:
        logger.warning("redis_unavailable", error=str(e))

    # Initialize orchestrator (shared with main API)
    dashboard_service._orchestrator = AgentOrchestrator(use_redis=False)
    await dashboard_service._orchestrator.initialize()

    dashboard_service._is_running = True

    # Start background tasks
    await dashboard_service.start_background_tasks()

    # Run server
    config = uvicorn.Config(
        dashboard_service.app,
        host=dashboard_service.host,
        port=dashboard_service.port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
