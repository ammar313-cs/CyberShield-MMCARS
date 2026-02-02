"""
Upstream Forwarder

Handles forwarding requests to upstream servers with load balancing,
health checking, and circuit breaker functionality.
"""

import asyncio
import random
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import structlog
import httpx

from src.proxy.config import UpstreamServer, LoadBalanceStrategy

logger = structlog.get_logger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class UpstreamHealth:
    """Health status for an upstream server."""

    server: UpstreamServer
    is_healthy: bool = True
    consecutive_failures: int = 0
    last_check: datetime = field(default_factory=datetime.utcnow)
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    response_times: List[float] = field(default_factory=list)
    active_connections: int = 0

    @property
    def avg_response_time(self) -> float:
        """Get average response time in ms."""
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)


@dataclass
class ForwardResult:
    """Result of forwarding a request."""

    success: bool = False
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    upstream_server: Optional[str] = None
    response_time_ms: float = 0.0
    error: Optional[str] = None
    retried: bool = False


class CircuitBreaker:
    """Circuit breaker for an upstream server."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 30,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.success_count = 0

    def record_success(self) -> None:
        """Record a successful request."""
        self.failure_count = 0
        self.success_count += 1

        if self.state == CircuitState.HALF_OPEN:
            # Successfully recovered
            self.state = CircuitState.CLOSED
            logger.info("circuit_breaker_closed")

    def record_failure(self) -> None:
        """Record a failed request."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        self.success_count = 0

        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(
                "circuit_breaker_opened",
                failures=self.failure_count,
            )

    def can_execute(self) -> bool:
        """Check if request can be executed."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self.last_failure_time:
                elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()
                if elapsed >= self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    logger.info("circuit_breaker_half_open")
                    return True
            return False

        # HALF_OPEN: allow one request to test
        return True


class UpstreamForwarder:
    """
    Forwards requests to upstream servers.

    Features:
    - Load balancing (round-robin, least connections, random, IP hash, weighted)
    - Health checking
    - Circuit breaker pattern
    - Connection pooling
    - Automatic retries
    """

    def __init__(
        self,
        upstream_servers: List[UpstreamServer],
        strategy: LoadBalanceStrategy = LoadBalanceStrategy.ROUND_ROBIN,
        request_timeout: float = 30.0,
        connect_timeout: float = 5.0,
        max_retries: int = 2,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: int = 30,
    ):
        self.upstream_servers = upstream_servers
        self.strategy = strategy
        self.request_timeout = request_timeout
        self.connect_timeout = connect_timeout
        self.max_retries = max_retries

        # Health tracking
        self._health: Dict[str, UpstreamHealth] = {}
        for server in upstream_servers:
            self._health[server.url] = UpstreamHealth(server=server)

        # Circuit breakers
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        for server in upstream_servers:
            self._circuit_breakers[server.url] = CircuitBreaker(
                failure_threshold=circuit_breaker_threshold,
                recovery_timeout=circuit_breaker_timeout,
            )

        # Round-robin index
        self._rr_index = 0

        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None

        # Statistics
        self._total_forwarded = 0
        self._successful_forwards = 0
        self._failed_forwards = 0

        logger.info(
            "upstream_forwarder_initialized",
            servers=len(upstream_servers),
            strategy=strategy.value,
        )

    async def initialize(self) -> None:
        """Initialize the HTTP client."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=self.connect_timeout,
                read=self.request_timeout,
                write=self.request_timeout,
                pool=self.connect_timeout,
            ),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
            follow_redirects=False,
        )
        logger.info("http_client_initialized")

    async def shutdown(self) -> None:
        """Shutdown the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("http_client_shutdown")

    async def forward(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None,
        query_string: str = "",
        client_ip: Optional[str] = None,
    ) -> ForwardResult:
        """
        Forward a request to an upstream server.

        Args:
            method: HTTP method
            path: Request path
            headers: Request headers
            body: Request body
            query_string: Query string
            client_ip: Client IP for IP hash load balancing

        Returns:
            ForwardResult with response or error
        """
        if not self._client:
            await self.initialize()

        self._total_forwarded += 1
        retry_count = 0
        last_error = None

        while retry_count <= self.max_retries:
            # Select upstream server
            server = self._select_server(client_ip)
            if not server:
                return ForwardResult(
                    success=False,
                    error="No healthy upstream servers available",
                )

            # Check circuit breaker
            circuit = self._circuit_breakers.get(server.url)
            if circuit and not circuit.can_execute():
                logger.debug("circuit_breaker_rejected", server=server.url)
                retry_count += 1
                continue

            # Build URL
            url = f"{server.url}{path}"
            if query_string:
                url = f"{url}?{query_string}"

            # Prepare headers
            forward_headers = dict(headers)
            forward_headers["X-Forwarded-For"] = client_ip or "unknown"
            forward_headers["X-Forwarded-Proto"] = "https" if server.ssl else "http"

            # Remove hop-by-hop headers
            hop_headers = [
                "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailers", "transfer-encoding",
                "upgrade",
            ]
            for h in hop_headers:
                forward_headers.pop(h, None)
                forward_headers.pop(h.title(), None)

            # Track timing
            start_time = datetime.utcnow()
            health = self._health.get(server.url)

            try:
                if health:
                    health.active_connections += 1

                # Make request
                response = await self._client.request(
                    method=method,
                    url=url,
                    headers=forward_headers,
                    content=body,
                )

                # Calculate response time
                response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

                # Update health
                if health:
                    health.active_connections = max(0, health.active_connections - 1)
                    health.is_healthy = True
                    health.consecutive_failures = 0
                    health.last_success = datetime.utcnow()
                    health.response_times.append(response_time)
                    # Keep only last 100 response times
                    if len(health.response_times) > 100:
                        health.response_times = health.response_times[-100:]

                # Update circuit breaker
                if circuit:
                    circuit.record_success()

                self._successful_forwards += 1

                # Build response headers
                response_headers = dict(response.headers)
                response_headers.pop("transfer-encoding", None)

                return ForwardResult(
                    success=True,
                    status_code=response.status_code,
                    headers=response_headers,
                    body=response.content,
                    upstream_server=server.url,
                    response_time_ms=response_time,
                    retried=retry_count > 0,
                )

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "upstream_request_failed",
                    server=server.url,
                    error=last_error,
                    retry=retry_count,
                )

                # Update health
                if health:
                    health.active_connections = max(0, health.active_connections - 1)
                    health.consecutive_failures += 1
                    health.last_failure = datetime.utcnow()
                    if health.consecutive_failures >= 3:
                        health.is_healthy = False

                # Update circuit breaker
                if circuit:
                    circuit.record_failure()

                retry_count += 1

        # All retries failed
        self._failed_forwards += 1
        return ForwardResult(
            success=False,
            error=f"All upstream servers failed: {last_error}",
            retried=True,
        )

    def _select_server(self, client_ip: Optional[str] = None) -> Optional[UpstreamServer]:
        """Select an upstream server based on load balancing strategy."""
        # Get healthy servers
        healthy_servers = [
            server for server in self.upstream_servers
            if self._health.get(server.url, UpstreamHealth(server=server)).is_healthy
        ]

        if not healthy_servers:
            # Try all servers if none are healthy
            healthy_servers = self.upstream_servers

        if not healthy_servers:
            return None

        if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
            server = healthy_servers[self._rr_index % len(healthy_servers)]
            self._rr_index += 1
            return server

        elif self.strategy == LoadBalanceStrategy.RANDOM:
            return random.choice(healthy_servers)

        elif self.strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
            return min(
                healthy_servers,
                key=lambda s: self._health.get(s.url, UpstreamHealth(server=s)).active_connections,
            )

        elif self.strategy == LoadBalanceStrategy.IP_HASH:
            if client_ip:
                hash_val = int(hashlib.md5(client_ip.encode()).hexdigest(), 16)
                return healthy_servers[hash_val % len(healthy_servers)]
            return healthy_servers[0]

        elif self.strategy == LoadBalanceStrategy.WEIGHTED:
            # Weighted random selection
            total_weight = sum(s.weight for s in healthy_servers)
            r = random.uniform(0, total_weight)
            current = 0
            for server in healthy_servers:
                current += server.weight
                if current >= r:
                    return server
            return healthy_servers[-1]

        return healthy_servers[0]

    async def health_check(self, server: UpstreamServer) -> bool:
        """Perform health check on an upstream server."""
        if not self._client:
            await self.initialize()

        url = f"{server.url}{server.health_check_path}"

        try:
            response = await self._client.get(
                url,
                timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=2.0),
            )

            is_healthy = 200 <= response.status_code < 400

            health = self._health.get(server.url)
            if health:
                health.is_healthy = is_healthy
                health.last_check = datetime.utcnow()
                if is_healthy:
                    health.consecutive_failures = 0
                    health.last_success = datetime.utcnow()

            return is_healthy

        except Exception as e:
            logger.warning(
                "health_check_failed",
                server=server.url,
                error=str(e),
            )

            health = self._health.get(server.url)
            if health:
                health.is_healthy = False
                health.consecutive_failures += 1
                health.last_check = datetime.utcnow()
                health.last_failure = datetime.utcnow()

            return False

    async def health_check_all(self) -> Dict[str, bool]:
        """Perform health checks on all upstream servers."""
        results = {}
        for server in self.upstream_servers:
            results[server.url] = await self.health_check(server)
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get forwarder statistics."""
        server_stats = {}
        for url, health in self._health.items():
            circuit = self._circuit_breakers.get(url)
            server_stats[url] = {
                "is_healthy": health.is_healthy,
                "consecutive_failures": health.consecutive_failures,
                "active_connections": health.active_connections,
                "avg_response_time_ms": round(health.avg_response_time, 2),
                "circuit_state": circuit.state.value if circuit else "unknown",
            }

        return {
            "total_forwarded": self._total_forwarded,
            "successful_forwards": self._successful_forwards,
            "failed_forwards": self._failed_forwards,
            "success_rate": (
                self._successful_forwards / self._total_forwarded
                if self._total_forwarded > 0
                else 0.0
            ),
            "strategy": self.strategy.value,
            "servers": server_stats,
        }

    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of all upstream servers."""
        return {
            url: {
                "is_healthy": health.is_healthy,
                "last_check": health.last_check.isoformat() if health.last_check else None,
                "consecutive_failures": health.consecutive_failures,
            }
            for url, health in self._health.items()
        }
