"""
Reverse Proxy Gateway

Main gateway component that inspects, analyzes, and forwards traffic
to upstream servers while providing threat protection.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional
import structlog

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from src.proxy.config import ProxyConfig, InspectionMode
from src.proxy.inspector import TrafficInspector, RequestContext, InspectionResult
from src.proxy.forwarder import UpstreamForwarder, ForwardResult
from src.agents.coordinator.orchestrator import AgentOrchestrator
from src.domain.events.threat_detected import ThreatDetectedEvent
from src.infrastructure.persistence.redis_client import get_redis, init_redis, close_redis

logger = structlog.get_logger(__name__)


class ReverseProxyGateway:
    """
    CyberShield Reverse Proxy Gateway.

    Acts as a security gateway that:
    1. Receives all incoming traffic
    2. Inspects and analyzes for threats
    3. Blocks malicious requests
    4. Forwards clean traffic to upstream servers
    5. Integrates with the agent orchestrator for advanced threat response
    """

    def __init__(
        self,
        config: ProxyConfig,
        orchestrator: Optional[AgentOrchestrator] = None,
    ):
        self.config = config
        self.orchestrator = orchestrator

        # Initialize components
        self.inspector = TrafficInspector(
            mode=config.inspection_mode,
            threat_threshold=config.threat_threshold,
            enable_ml=config.enable_ml_detection,
            enable_pattern_matching=config.enable_pattern_matching,
        )

        self.forwarder = UpstreamForwarder(
            upstream_servers=config.upstream_servers,
            strategy=config.load_balance_strategy,
            request_timeout=config.request_timeout,
            connect_timeout=config.connect_timeout,
            circuit_breaker_threshold=config.circuit_breaker_threshold,
            circuit_breaker_timeout=config.circuit_breaker_timeout,
        )

        # FastAPI app for the proxy
        self.app: Optional[FastAPI] = None

        # Statistics
        self._stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "forwarded_requests": 0,
            "failed_forwards": 0,
            "threats_detected": 0,
            "start_time": None,
        }

        logger.info(
            "reverse_proxy_gateway_created",
            upstreams=len(config.upstream_servers),
            mode=config.inspection_mode.value,
        )

    def create_app(self) -> FastAPI:
        """Create the FastAPI application for the proxy gateway."""

        @asynccontextmanager
        async def lifespan(app: FastAPI) -> AsyncGenerator:
            """Application lifespan manager."""
            logger.info("starting_reverse_proxy_gateway")
            self._stats["start_time"] = datetime.utcnow()

            # Initialize Redis
            try:
                await init_redis()
                logger.info("redis_connected")
            except Exception as e:
                logger.warning("redis_connection_failed", error=str(e))

            # Initialize forwarder
            await self.forwarder.initialize()

            # Initialize orchestrator if provided
            if self.orchestrator:
                await self.orchestrator.initialize()

            yield

            # Shutdown
            logger.info("shutting_down_reverse_proxy_gateway")
            await self.forwarder.shutdown()
            if self.orchestrator:
                await self.orchestrator.shutdown()
            await close_redis()

        self.app = FastAPI(
            title="CyberShield Reverse Proxy",
            description="Security Gateway with Threat Detection",
            version="0.1.0",
            lifespan=lifespan,
            docs_url=None,  # Disable docs in proxy mode
            redoc_url=None,
        )

        # Proxy status endpoint
        @self.app.get("/_proxy/status")
        async def proxy_status():
            """Get proxy gateway status."""
            return {
                "status": "running",
                "mode": self.config.inspection_mode.value,
                "upstreams": len(self.config.upstream_servers),
                "stats": self.get_stats(),
            }

        # Proxy health endpoint
        @self.app.get("/_proxy/health")
        async def proxy_health():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "upstreams": self.forwarder.get_health_status(),
            }

        # Inspector stats endpoint
        @self.app.get("/_proxy/inspector/stats")
        async def inspector_stats():
            """Get traffic inspector statistics."""
            return self.inspector.get_stats()

        # Forwarder stats endpoint
        @self.app.get("/_proxy/forwarder/stats")
        async def forwarder_stats():
            """Get upstream forwarder statistics."""
            return self.forwarder.get_stats()

        # Block IP endpoint
        @self.app.post("/_proxy/block/{ip}")
        async def block_ip(ip: str):
            """Block an IP address."""
            self.inspector.block_ip(ip)
            return {"status": "blocked", "ip": ip}

        # Unblock IP endpoint
        @self.app.post("/_proxy/unblock/{ip}")
        async def unblock_ip(ip: str):
            """Unblock an IP address."""
            self.inspector.unblock_ip(ip)
            return {"status": "unblocked", "ip": ip}

        # Catch-all route for proxying
        @self.app.api_route(
            "/{path:path}",
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        )
        async def proxy_request(request: Request, path: str):
            """Proxy all requests through the gateway."""
            return await self._handle_request(request, path)

        # WebSocket proxying
        if self.config.enable_websocket:
            @self.app.websocket("/{path:path}")
            async def proxy_websocket(websocket: WebSocket, path: str):
                """Proxy WebSocket connections."""
                await self._handle_websocket(websocket, path)

        return self.app

    async def _handle_request(self, request: Request, path: str) -> Response:
        """
        Handle an incoming HTTP request.

        1. Extract request details
        2. Inspect for threats
        3. Block or forward based on inspection result
        """
        self._stats["total_requests"] += 1
        start_time = datetime.utcnow()

        # Extract client IP
        client_ip = self._get_client_ip(request)

        # Check allowed IPs (bypass inspection)
        if client_ip in self.config.allowed_ips:
            return await self._forward_request(request, path, client_ip)

        # Check blocked IPs
        if client_ip in self.config.blocked_ips:
            self._stats["blocked_requests"] += 1
            logger.warning("request_blocked_ip_list", client_ip=client_ip, path=path)
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "reason": "IP blocked"},
            )

        # Read request body
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()

            # Check body size
            if len(body) > self.config.max_request_size:
                self._stats["blocked_requests"] += 1
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request entity too large"},
                )

        # Build request context for inspection
        context = RequestContext(
            client_ip=client_ip,
            method=request.method,
            path=f"/{path}",
            query_string=str(request.url.query),
            headers=dict(request.headers),
            body=body,
            content_type=request.headers.get("content-type"),
            user_agent=request.headers.get("user-agent"),
        )

        # Inspect traffic
        inspection_result = await self.inspector.inspect(context)

        # Log inspection result
        if inspection_result.is_threat:
            self._stats["threats_detected"] += 1
            logger.warning(
                "threat_detected",
                client_ip=client_ip,
                path=path,
                threat_type=inspection_result.threat_type.value,
                confidence=inspection_result.confidence,
                indicators=inspection_result.indicators,
            )

            # Trigger orchestrator if available
            if self.orchestrator and inspection_result.confidence >= 0.8:
                asyncio.create_task(
                    self._handle_threat_async(context, inspection_result)
                )

        # Block if needed
        if inspection_result.should_block:
            self._stats["blocked_requests"] += 1

            # Add to blocked list for high-confidence threats
            if inspection_result.confidence >= 0.95:
                self.inspector.block_ip(client_ip)
                self.config.blocked_ips.add(client_ip)

            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access denied",
                    "reason": inspection_result.threat_type.value,
                    "details": inspection_result.details,
                },
            )

        # Forward request to upstream
        return await self._forward_request(request, path, client_ip, body)

    async def _forward_request(
        self,
        request: Request,
        path: str,
        client_ip: str,
        body: Optional[bytes] = None,
    ) -> Response:
        """Forward request to upstream server."""
        # Read body if not already read
        if body is None and request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()

        # Strip path prefix if configured
        if self.config.strip_path_prefix and path.startswith(self.config.strip_path_prefix):
            path = path[len(self.config.strip_path_prefix):]

        # Ensure path starts with /
        if not path.startswith("/"):
            path = f"/{path}"

        # Prepare headers
        headers = dict(request.headers)

        # Remove/add headers as configured
        for header in self.config.remove_headers:
            headers.pop(header, None)
            headers.pop(header.lower(), None)

        for key, value in self.config.add_headers.items():
            headers[key] = value

        # Preserve or override host
        if not self.config.preserve_host:
            headers.pop("host", None)
            headers.pop("Host", None)

        # Forward request
        result = await self.forwarder.forward(
            method=request.method,
            path=path,
            headers=headers,
            body=body,
            query_string=str(request.url.query),
            client_ip=client_ip,
        )

        if result.success:
            self._stats["forwarded_requests"] += 1

            # Add proxy headers to response
            response_headers = dict(result.headers)
            response_headers["X-Proxy-Response-Time"] = f"{result.response_time_ms:.2f}ms"
            response_headers["X-Upstream-Server"] = result.upstream_server or "unknown"

            return Response(
                content=result.body,
                status_code=result.status_code,
                headers=response_headers,
            )
        else:
            self._stats["failed_forwards"] += 1
            logger.error(
                "forward_failed",
                path=path,
                error=result.error,
            )

            return JSONResponse(
                status_code=502,
                content={
                    "error": "Bad Gateway",
                    "details": result.error,
                },
            )

    async def _handle_websocket(self, websocket: WebSocket, path: str) -> None:
        """Handle WebSocket connection proxying."""
        client_ip = self._get_client_ip_ws(websocket)

        # Check blocked IPs
        if client_ip in self.config.blocked_ips:
            await websocket.close(code=4003, reason="Access denied")
            return

        # Accept the WebSocket connection
        await websocket.accept()

        # For now, just close with "not implemented"
        # Full WebSocket proxying requires more complex handling
        logger.info("websocket_proxy_not_implemented", path=path)
        await websocket.close(code=4000, reason="WebSocket proxying not yet implemented")

    async def _handle_threat_async(
        self,
        context: RequestContext,
        inspection_result: InspectionResult,
    ) -> None:
        """Handle threat detection asynchronously via orchestrator."""
        try:
            if not self.orchestrator:
                return

            # Create threat event
            from src.domain.entities.traffic_event import TrafficEvent
            from src.domain.value_objects.ip_address import IPAddress

            # Map inspection result to severity
            if inspection_result.confidence >= 0.95:
                severity = "critical"
            elif inspection_result.confidence >= 0.85:
                severity = "high"
            elif inspection_result.confidence >= 0.7:
                severity = "medium"
            else:
                severity = "low"

            # Create a synthetic traffic event for the orchestrator
            event = TrafficEvent(
                source_ip=IPAddress(context.client_ip),
                destination_ip=IPAddress("10.0.0.1"),  # Internal
                source_port=0,
                destination_port=443,
                protocol="https",
                packet_size=len(context.body) if context.body else 0,
                timestamp=context.timestamp,
                flags=["PSH", "ACK"],
                metadata={
                    "path": context.path,
                    "method": context.method,
                    "user_agent": context.user_agent,
                    "threat_type": inspection_result.threat_type.value,
                    "indicators": inspection_result.indicators,
                },
            )

            # Process through orchestrator
            await self.orchestrator.process_event(event)

        except Exception as e:
            logger.error("threat_handling_failed", error=str(e))

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        if request.client:
            return request.client.host

        return "unknown"

    def _get_client_ip_ws(self, websocket: WebSocket) -> str:
        """Extract client IP from WebSocket connection."""
        forwarded = websocket.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        if websocket.client:
            return websocket.client.host

        return "unknown"

    def get_stats(self) -> Dict[str, Any]:
        """Get gateway statistics."""
        uptime = None
        if self._stats["start_time"]:
            uptime = (datetime.utcnow() - self._stats["start_time"]).total_seconds()

        return {
            "total_requests": self._stats["total_requests"],
            "blocked_requests": self._stats["blocked_requests"],
            "forwarded_requests": self._stats["forwarded_requests"],
            "failed_forwards": self._stats["failed_forwards"],
            "threats_detected": self._stats["threats_detected"],
            "uptime_seconds": uptime,
            "block_rate": (
                self._stats["blocked_requests"] / self._stats["total_requests"]
                if self._stats["total_requests"] > 0
                else 0.0
            ),
            "inspector": self.inspector.get_stats(),
            "forwarder": self.forwarder.get_stats(),
        }


def create_proxy_app(
    config: Optional[ProxyConfig] = None,
    orchestrator: Optional[AgentOrchestrator] = None,
) -> FastAPI:
    """
    Create a FastAPI application for the reverse proxy gateway.

    Args:
        config: Proxy configuration (or load from environment)
        orchestrator: Optional agent orchestrator for advanced threat response

    Returns:
        Configured FastAPI application
    """
    if config is None:
        config = ProxyConfig.from_env()

    # Validate configuration
    errors = config.validate()
    if errors:
        logger.error("proxy_config_invalid", errors=errors)
        raise ValueError(f"Invalid proxy configuration: {errors}")

    gateway = ReverseProxyGateway(config=config, orchestrator=orchestrator)
    return gateway.create_app()
