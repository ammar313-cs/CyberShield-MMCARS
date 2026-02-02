"""
Docker Health Checker
Checks container health status via Docker API.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ContainerHealth:
    """Health status for a Docker container."""
    container_name: str
    running: bool
    healthy: Optional[bool]  # None if no healthcheck configured
    status: str
    started_at: Optional[datetime]
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "container_name": self.container_name,
            "running": self.running,
            "healthy": self.healthy,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "error_message": self.error_message,
        }


# Container name to component mapping
CONTAINER_COMPONENT_MAP = {
    "cybershield-redis": "redis_cache",
    "cybershield-api": "api_gateway",
    "cybershield-ml": "detection_engine",
    "cybershield-agents": "agent_coordinator",
    "cybershield-proxy": "response_system",
    "cybershield-dashboard": "dashboard",
}


class DockerHealthChecker:
    """
    Checks Docker container health status.

    Uses aiodocker for async Docker API access.
    Requires Docker socket to be mounted at /var/run/docker.sock
    """

    def __init__(self):
        self._docker = None
        self._available = False

    async def initialize(self) -> bool:
        """
        Initialize Docker client.

        Returns:
            True if Docker API is available
        """
        try:
            # Try to import aiodocker
            import aiodocker
            self._docker = aiodocker.Docker()
            # Test connection
            await self._docker.version()
            self._available = True
            logger.info("docker_api_available")
            return True
        except ImportError:
            logger.warning("aiodocker_not_installed")
            return False
        except Exception as e:
            logger.warning("docker_api_not_available", error=str(e))
            return False

    async def close(self) -> None:
        """Close Docker client."""
        if self._docker:
            await self._docker.close()

    async def check_container(self, container_name: str) -> ContainerHealth:
        """
        Check health status of a specific container.

        Args:
            container_name: Name of the container to check

        Returns:
            ContainerHealth with status information
        """
        if not self._available or not self._docker:
            return ContainerHealth(
                container_name=container_name,
                running=False,
                healthy=None,
                status="unknown",
                started_at=None,
                error_message="Docker API not available",
            )

        try:
            containers = await self._docker.containers.list(
                filters={"name": [container_name]}
            )

            if not containers:
                return ContainerHealth(
                    container_name=container_name,
                    running=False,
                    healthy=None,
                    status="not_found",
                    started_at=None,
                )

            container = containers[0]
            info = await container.show()

            state = info.get("State", {})
            running = state.get("Running", False)
            status = state.get("Status", "unknown")

            # Parse started_at timestamp
            started_at = None
            started_at_str = state.get("StartedAt")
            if started_at_str and started_at_str != "0001-01-01T00:00:00Z":
                try:
                    # Docker timestamps are in ISO format with nanoseconds
                    started_at = datetime.fromisoformat(
                        started_at_str.replace("Z", "+00:00").split(".")[0]
                    )
                except (ValueError, IndexError):
                    pass

            # Check health status if configured
            health = state.get("Health", {})
            healthy = None
            if health:
                health_status = health.get("Status", "")
                healthy = health_status == "healthy"

            return ContainerHealth(
                container_name=container_name,
                running=running,
                healthy=healthy,
                status=status,
                started_at=started_at,
            )

        except Exception as e:
            logger.error("container_health_check_failed", container=container_name, error=str(e))
            return ContainerHealth(
                container_name=container_name,
                running=False,
                healthy=None,
                status="error",
                started_at=None,
                error_message=str(e),
            )

    async def check_all_containers(self) -> dict[str, ContainerHealth]:
        """
        Check all CyberShield containers.

        Returns:
            Dict mapping container name to ContainerHealth
        """
        if not self._available:
            return {
                name: ContainerHealth(
                    container_name=name,
                    running=False,
                    healthy=None,
                    status="docker_unavailable",
                    started_at=None,
                )
                for name in CONTAINER_COMPONENT_MAP.keys()
            }

        # Check all containers in parallel
        tasks = [
            self.check_container(name)
            for name in CONTAINER_COMPONENT_MAP.keys()
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        health_results = {}
        for name, result in zip(CONTAINER_COMPONENT_MAP.keys(), results):
            if isinstance(result, Exception):
                health_results[name] = ContainerHealth(
                    container_name=name,
                    running=False,
                    healthy=None,
                    status="error",
                    started_at=None,
                    error_message=str(result),
                )
            else:
                health_results[name] = result

        return health_results

    def map_to_component_status(
        self,
        container_health: dict[str, ContainerHealth],
    ) -> dict[str, str]:
        """
        Map container health to component status strings.

        Returns:
            Dict mapping component name to status ("healthy", "degraded", "critical")
        """
        component_status = {}

        for container_name, health in container_health.items():
            component = CONTAINER_COMPONENT_MAP.get(container_name)
            if not component:
                continue

            if not health.running:
                component_status[component] = "critical"
            elif health.healthy is False:
                component_status[component] = "degraded"
            elif health.healthy is True:
                component_status[component] = "healthy"
            else:
                # No healthcheck configured, rely on running status
                component_status[component] = "healthy" if health.running else "critical"

        return component_status
