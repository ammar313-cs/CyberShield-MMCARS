"""
Health Checker Service
Performs actual service health checks for components.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import structlog

import httpx

from src.infrastructure.persistence.redis_client import RedisClient

logger = structlog.get_logger(__name__)


class HealthStatus(str, Enum):
    """Health status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ServiceHealth:
    """Health status for a single service."""
    name: str
    status: HealthStatus
    last_check: datetime
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "last_check": self.last_check.isoformat(),
            "response_time_ms": self.response_time_ms,
            "error_message": self.error_message,
            "details": self.details,
        }


# Redis keys for health persistence
HEALTH_COMPONENTS_KEY = "cybershield:health:components"
HEALTH_AGENTS_KEY = "cybershield:health:agents"


class HealthChecker:
    """
    Service health checker that performs actual health checks.

    Checks:
    - Redis: PING command
    - API Gateway: HTTP GET to health endpoint
    - ML Service: Redis key check or HTTP
    - Response System: Message bus connectivity
    - Agent Coordinator: Heartbeat check
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        api_base_url: str = None,
        check_timeout_seconds: float = 5.0,
    ):
        import os
        self._redis = redis_client
        # Use environment variable for API URL (for Docker networking)
        # Default to localhost for local development
        self._api_base_url = api_base_url or os.getenv("API_BASE_URL", "http://localhost:8000")
        self._timeout = check_timeout_seconds
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client

    async def close(self) -> None:
        """Close resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def check_redis(self) -> ServiceHealth:
        """
        Check Redis health via PING command.

        Returns:
            ServiceHealth for redis_cache component
        """
        start_time = datetime.utcnow()

        if not self._redis:
            return ServiceHealth(
                name="redis_cache",
                status=HealthStatus.UNKNOWN,
                last_check=start_time,
                error_message="Redis client not configured",
            )

        try:
            ping_start = datetime.utcnow()

            # Perform actual PING
            if self._redis._client:
                result = await asyncio.wait_for(
                    self._redis._client.ping(),
                    timeout=self._timeout,
                )
                response_time = (datetime.utcnow() - ping_start).total_seconds() * 1000

                if result:
                    # Check response time for degraded status
                    status = HealthStatus.HEALTHY
                    if response_time > 100:  # >100ms is degraded
                        status = HealthStatus.DEGRADED

                    return ServiceHealth(
                        name="redis_cache",
                        status=status,
                        last_check=datetime.utcnow(),
                        response_time_ms=response_time,
                        details={"ping_response": True},
                    )

            return ServiceHealth(
                name="redis_cache",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message="Redis client not connected",
            )

        except asyncio.TimeoutError:
            return ServiceHealth(
                name="redis_cache",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message="Redis PING timeout",
            )
        except Exception as e:
            logger.error("redis_health_check_failed", error=str(e))
            return ServiceHealth(
                name="redis_cache",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message=str(e),
            )

    async def check_api_gateway(self) -> ServiceHealth:
        """
        Check API Gateway health via HTTP endpoint.

        Returns:
            ServiceHealth for api_gateway component
        """
        start_time = datetime.utcnow()

        try:
            client = await self._get_http_client()

            response = await client.get(
                f"{self._api_base_url}/api/v1/health",
            )

            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            if response.status_code == 200:
                status = HealthStatus.HEALTHY
                if response_time > 500:  # >500ms is degraded
                    status = HealthStatus.DEGRADED

                return ServiceHealth(
                    name="api_gateway",
                    status=status,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    details={"status_code": response.status_code},
                )
            else:
                return ServiceHealth(
                    name="api_gateway",
                    status=HealthStatus.DEGRADED,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    error_message=f"HTTP {response.status_code}",
                    details={"status_code": response.status_code},
                )

        except httpx.ConnectError:
            return ServiceHealth(
                name="api_gateway",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message="Connection refused",
            )
        except httpx.TimeoutException:
            return ServiceHealth(
                name="api_gateway",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message="Request timeout",
            )
        except Exception as e:
            logger.error("api_gateway_health_check_failed", error=str(e))
            return ServiceHealth(
                name="api_gateway",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message=str(e),
            )

    async def check_detection_engine(self) -> ServiceHealth:
        """
        Check ML detection engine health.

        Checks if ML predictor is available via Redis key or direct check.

        Returns:
            ServiceHealth for detection_engine component
        """
        start_time = datetime.utcnow()

        if not self._redis or not self._redis._client:
            return ServiceHealth(
                name="detection_engine",
                status=HealthStatus.UNKNOWN,
                last_check=start_time,
                error_message="Cannot check - Redis unavailable",
            )

        try:
            # Check for ML service heartbeat in Redis
            heartbeat_key = "cybershield:heartbeat:ml_service"
            ml_heartbeat = await self._redis._client.get(heartbeat_key)

            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            if ml_heartbeat:
                return ServiceHealth(
                    name="detection_engine",
                    status=HealthStatus.HEALTHY,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    details={"heartbeat": ml_heartbeat},
                )
            else:
                # No heartbeat but might still be running - mark as degraded
                # In production, would have a more robust check
                return ServiceHealth(
                    name="detection_engine",
                    status=HealthStatus.DEGRADED,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    error_message="No heartbeat detected",
                )

        except Exception as e:
            logger.error("detection_engine_health_check_failed", error=str(e))
            return ServiceHealth(
                name="detection_engine",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message=str(e),
            )

    async def check_response_system(self) -> ServiceHealth:
        """
        Check response system (agent message bus) health.

        Returns:
            ServiceHealth for response_system component
        """
        start_time = datetime.utcnow()

        if not self._redis or not self._redis._client:
            return ServiceHealth(
                name="response_system",
                status=HealthStatus.UNKNOWN,
                last_check=start_time,
                error_message="Cannot check - Redis unavailable",
            )

        try:
            # Check message bus queue exists and is accessible
            queue_key = "cybershield:message_bus:queue"
            queue_exists = await self._redis._client.exists(queue_key)

            # Also check for agent heartbeats
            agent_keys = await self._redis._client.keys("cybershield:heartbeat:agent:*")
            active_agents = len(agent_keys) if agent_keys else 0

            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            if active_agents > 0:
                return ServiceHealth(
                    name="response_system",
                    status=HealthStatus.HEALTHY,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    details={
                        "active_agents": active_agents,
                        "queue_exists": bool(queue_exists),
                    },
                )
            else:
                return ServiceHealth(
                    name="response_system",
                    status=HealthStatus.DEGRADED,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    error_message="No active agents detected",
                    details={"queue_exists": bool(queue_exists)},
                )

        except Exception as e:
            logger.error("response_system_health_check_failed", error=str(e))
            return ServiceHealth(
                name="response_system",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message=str(e),
            )

    async def check_agent_coordinator(self) -> ServiceHealth:
        """
        Check agent coordinator (orchestrator) health.

        Returns:
            ServiceHealth for agent_coordinator component
        """
        start_time = datetime.utcnow()

        if not self._redis or not self._redis._client:
            return ServiceHealth(
                name="agent_coordinator",
                status=HealthStatus.UNKNOWN,
                last_check=start_time,
                error_message="Cannot check - Redis unavailable",
            )

        try:
            # Check orchestrator heartbeat
            heartbeat_key = "cybershield:heartbeat:orchestrator"
            orchestrator_heartbeat = await self._redis._client.get(heartbeat_key)

            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            if orchestrator_heartbeat:
                return ServiceHealth(
                    name="agent_coordinator",
                    status=HealthStatus.HEALTHY,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    details={"heartbeat": orchestrator_heartbeat},
                )
            else:
                return ServiceHealth(
                    name="agent_coordinator",
                    status=HealthStatus.DEGRADED,
                    last_check=datetime.utcnow(),
                    response_time_ms=response_time,
                    error_message="No orchestrator heartbeat",
                )

        except Exception as e:
            logger.error("agent_coordinator_health_check_failed", error=str(e))
            return ServiceHealth(
                name="agent_coordinator",
                status=HealthStatus.UNHEALTHY,
                last_check=datetime.utcnow(),
                error_message=str(e),
            )

    async def check_all_components(self) -> dict[str, ServiceHealth]:
        """
        Check all components in parallel.

        Returns:
            Dict mapping component name to ServiceHealth
        """
        # Run all checks concurrently
        results = await asyncio.gather(
            self.check_redis(),
            self.check_api_gateway(),
            self.check_detection_engine(),
            self.check_response_system(),
            self.check_agent_coordinator(),
            return_exceptions=True,
        )

        # Map results to component names
        component_names = [
            "redis_cache",
            "api_gateway",
            "detection_engine",
            "response_system",
            "agent_coordinator",
        ]

        health_results = {}
        for name, result in zip(component_names, results):
            if isinstance(result, Exception):
                health_results[name] = ServiceHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    last_check=datetime.utcnow(),
                    error_message=str(result),
                )
            else:
                health_results[name] = result

        # Persist to Redis if available
        await self._persist_health_status(health_results)

        return health_results

    async def _persist_health_status(
        self,
        health_results: dict[str, ServiceHealth],
    ) -> None:
        """Persist component health status to Redis."""
        if not self._redis or not self._redis._client:
            return

        try:
            import json

            # Store each component's health in a hash
            for name, health in health_results.items():
                await self._redis._client.hset(
                    HEALTH_COMPONENTS_KEY,
                    name,
                    json.dumps(health.to_dict()),
                )

            # Set TTL on the hash (health data expires after 60 seconds)
            await self._redis._client.expire(HEALTH_COMPONENTS_KEY, 60)

        except Exception as e:
            logger.error("failed_to_persist_health_status", error=str(e))

    async def get_persisted_health(self) -> dict[str, dict]:
        """
        Get persisted health status from Redis.

        Returns:
            Dict of component health data
        """
        if not self._redis or not self._redis._client:
            return {}

        try:
            import json

            health_data = await self._redis._client.hgetall(HEALTH_COMPONENTS_KEY)
            return {
                name: json.loads(data) for name, data in health_data.items()
            }
        except Exception as e:
            logger.error("failed_to_get_persisted_health", error=str(e))
            return {}

    def get_status_string(self, health: ServiceHealth) -> str:
        """
        Convert ServiceHealth to simple status string for backward compatibility.

        Returns:
            "healthy", "degraded", or "critical" (maps unhealthy to critical)
        """
        if health.status == HealthStatus.HEALTHY:
            return "healthy"
        elif health.status == HealthStatus.DEGRADED:
            return "degraded"
        else:
            return "critical"
