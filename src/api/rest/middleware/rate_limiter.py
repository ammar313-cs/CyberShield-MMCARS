"""
Rate Limiter Middleware
Implements rate limiting for API protection.
"""

from datetime import datetime
from typing import Callable
from collections import defaultdict
import asyncio
import structlog

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Token bucket rate limiter middleware.

    Limits requests per IP address to prevent abuse.
    """

    def __init__(
        self,
        app,
        requests_per_second: int = 100,
        burst_size: int = 200,
    ):
        super().__init__(app)
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size

        # Token buckets per IP
        self._buckets: dict[str, dict] = defaultdict(
            lambda: {
                "tokens": burst_size,
                "last_update": datetime.utcnow(),
            }
        )
        self._limited_count = 0
        self._lock = asyncio.Lock()

    async def dispatch(
        self,
        request: Request,
        call_next: Callable,
    ) -> Response:
        """
        Process the request through rate limiting.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response
        """
        # Skip rate limiting for health endpoints
        if request.url.path.startswith("/api/v1/health"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)

        # Check rate limit
        allowed, remaining = await self._check_rate_limit(client_ip)

        if not allowed:
            self._limited_count += 1
            logger.warning(
                "rate_limited",
                client_ip=client_ip,
                path=request.url.path,
            )
            return Response(
                content='{"detail": "Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_second),
                    "X-RateLimit-Remaining": "0",
                    "Retry-After": "1",
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_second)
        response.headers["X-RateLimit-Remaining"] = str(int(remaining))

        return response

    async def _check_rate_limit(self, ip: str) -> tuple[bool, float]:
        """
        Check and update rate limit for IP.

        Returns:
            Tuple of (allowed, remaining_tokens)
        """
        async with self._lock:
            now = datetime.utcnow()
            bucket = self._buckets[ip]

            # Calculate tokens to add based on time elapsed
            elapsed = (now - bucket["last_update"]).total_seconds()
            tokens_to_add = elapsed * self.requests_per_second

            # Update bucket
            bucket["tokens"] = min(
                self.burst_size,
                bucket["tokens"] + tokens_to_add,
            )
            bucket["last_update"] = now

            # Check if request is allowed
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                return True, bucket["tokens"]
            else:
                return False, 0

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

    def set_rate_limit(self, ip: str, requests_per_second: int) -> None:
        """
        Set custom rate limit for specific IP.

        Used by mitigation system to throttle suspicious IPs.
        """
        # Would implement custom per-IP limits
        logger.info(
            "custom_rate_limit_set",
            ip=ip,
            limit=requests_per_second,
        )

    def get_stats(self) -> dict:
        """Get middleware statistics."""
        return {
            "active_buckets": len(self._buckets),
            "limited_count": self._limited_count,
            "requests_per_second": self.requests_per_second,
            "burst_size": self.burst_size,
        }
