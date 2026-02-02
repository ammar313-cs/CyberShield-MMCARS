"""
Traffic Interceptor Middleware
Intercepts and analyzes incoming traffic for threats.
"""

from datetime import datetime
from typing import Callable
import structlog

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)


class TrafficInterceptorMiddleware(BaseHTTPMiddleware):
    """
    Middleware that intercepts traffic for analysis.

    Records request metadata for potential threat analysis.
    """

    def __init__(self, app, analyze_traffic: bool = True):
        super().__init__(app)
        self.analyze_traffic = analyze_traffic
        self._request_count = 0
        self._blocked_count = 0

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """
        Process the request through the middleware.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response
        """
        start_time = datetime.utcnow()
        self._request_count += 1

        # Extract request metadata
        client_ip = self._get_client_ip(request)
        request_path = request.url.path
        method = request.method

        # Log request (could be sent to analysis queue)
        logger.debug(
            "request_intercepted",
            client_ip=client_ip,
            path=request_path,
            method=method,
        )

        # Check if IP is blocked (would check against blocked list)
        if await self._is_blocked(client_ip):
            self._blocked_count += 1
            logger.warning(
                "request_blocked",
                client_ip=client_ip,
                path=request_path,
            )
            return Response(
                content='{"detail": "Access denied"}',
                status_code=403,
                media_type="application/json",
            )

        # Process request
        response = await call_next(request)

        # Calculate response time
        duration = (datetime.utcnow() - start_time).total_seconds() * 1000

        # Log response
        logger.debug(
            "request_completed",
            client_ip=client_ip,
            path=request_path,
            status_code=response.status_code,
            duration_ms=f"{duration:.2f}",
        )

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to client host
        if request.client:
            return request.client.host

        return "unknown"

    async def _is_blocked(self, ip: str) -> bool:
        """
        Check if IP is blocked.

        In production, would check Redis or local cache.
        """
        # Placeholder - would check actual blocked list
        return False

    def get_stats(self) -> dict:
        """Get middleware statistics."""
        return {
            "request_count": self._request_count,
            "blocked_count": self._blocked_count,
            "block_rate": (
                self._blocked_count / self._request_count
                if self._request_count > 0
                else 0.0
            ),
        }
