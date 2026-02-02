"""
Heartbeat Management
Tracks agent heartbeats and determines health status.
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
import structlog

from src.infrastructure.persistence.redis_client import RedisClient

logger = structlog.get_logger(__name__)


class AgentStatus(str, Enum):
    """Agent health status values."""
    ACTIVE = "active"
    IDLE = "idle"
    UNRESPONSIVE = "unresponsive"
    ERROR = "error"


@dataclass
class AgentHeartbeat:
    """Heartbeat data for an agent."""
    agent_id: str
    agent_type: str
    last_heartbeat: datetime
    status: AgentStatus
    error_count: int = 0
    processing: bool = False
    last_activity: Optional[datetime] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "status": self.status.value,
            "error_count": self.error_count,
            "processing": self.processing,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AgentHeartbeat":
        """Create from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            agent_type=data["agent_type"],
            last_heartbeat=datetime.fromisoformat(data["last_heartbeat"]),
            status=AgentStatus(data["status"]),
            error_count=data.get("error_count", 0),
            processing=data.get("processing", False),
            last_activity=datetime.fromisoformat(data["last_activity"]) if data.get("last_activity") else None,
            metadata=data.get("metadata", {}),
        )


# Redis key patterns
HEARTBEAT_KEY_PREFIX = "cybershield:heartbeat:agent:"
HEALTH_AGENTS_KEY = "cybershield:health:agents"

# Default thresholds
DEFAULT_IDLE_THRESHOLD_SECONDS = 30
DEFAULT_UNRESPONSIVE_THRESHOLD_SECONDS = 60
DEFAULT_ERROR_THRESHOLD = 5


class HeartbeatManager:
    """
    Manages agent heartbeats and determines health status.

    Features:
    - Records heartbeats from agents
    - Determines agent status based on last heartbeat time
    - Tracks error counts for error status
    - Persists heartbeat data to Redis for cross-service visibility
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        idle_threshold_seconds: int = DEFAULT_IDLE_THRESHOLD_SECONDS,
        unresponsive_threshold_seconds: int = DEFAULT_UNRESPONSIVE_THRESHOLD_SECONDS,
        error_threshold: int = DEFAULT_ERROR_THRESHOLD,
    ):
        self._redis = redis_client
        self._idle_threshold = timedelta(seconds=idle_threshold_seconds)
        self._unresponsive_threshold = timedelta(seconds=unresponsive_threshold_seconds)
        self._error_threshold = error_threshold

        # In-memory heartbeat cache (for when Redis is unavailable)
        self._heartbeats: dict[str, AgentHeartbeat] = {}

    async def record_heartbeat(
        self,
        agent_id: str,
        agent_type: str,
        processing: bool = False,
        metadata: Optional[dict] = None,
    ) -> AgentHeartbeat:
        """
        Record a heartbeat from an agent.

        Args:
            agent_id: Unique agent identifier
            agent_type: Type of agent (analyzer, responder, etc.)
            processing: Whether agent is currently processing
            metadata: Additional metadata

        Returns:
            Updated AgentHeartbeat
        """
        now = datetime.utcnow()

        # Get existing heartbeat or create new
        if agent_id in self._heartbeats:
            heartbeat = self._heartbeats[agent_id]
            heartbeat.last_heartbeat = now
            heartbeat.processing = processing
            if metadata:
                heartbeat.metadata.update(metadata)
            # Reset error count on successful heartbeat
            heartbeat.error_count = max(0, heartbeat.error_count - 1)
        else:
            heartbeat = AgentHeartbeat(
                agent_id=agent_id,
                agent_type=agent_type,
                last_heartbeat=now,
                status=AgentStatus.ACTIVE,
                processing=processing,
                last_activity=now,
                metadata=metadata or {},
            )

        # Update status
        heartbeat.status = self._determine_status(heartbeat)
        self._heartbeats[agent_id] = heartbeat

        # Persist to Redis
        await self._persist_heartbeat(heartbeat)

        return heartbeat

    async def record_activity(self, agent_id: str) -> None:
        """
        Record that an agent performed an activity.

        Args:
            agent_id: Agent identifier
        """
        if agent_id in self._heartbeats:
            self._heartbeats[agent_id].last_activity = datetime.utcnow()
            self._heartbeats[agent_id].last_heartbeat = datetime.utcnow()
            await self._persist_heartbeat(self._heartbeats[agent_id])

    async def record_error(self, agent_id: str, error_message: Optional[str] = None) -> None:
        """
        Record an error for an agent.

        Args:
            agent_id: Agent identifier
            error_message: Optional error message
        """
        if agent_id in self._heartbeats:
            self._heartbeats[agent_id].error_count += 1
            self._heartbeats[agent_id].status = self._determine_status(
                self._heartbeats[agent_id]
            )
            if error_message:
                self._heartbeats[agent_id].metadata["last_error"] = error_message
            await self._persist_heartbeat(self._heartbeats[agent_id])

    def get_status(self, agent_id: str) -> AgentStatus:
        """
        Get current status for an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            AgentStatus (active, idle, unresponsive, or error)
        """
        if agent_id not in self._heartbeats:
            return AgentStatus.UNRESPONSIVE

        heartbeat = self._heartbeats[agent_id]
        return self._determine_status(heartbeat)

    def _determine_status(self, heartbeat: AgentHeartbeat) -> AgentStatus:
        """
        Determine agent status based on heartbeat data.

        Status logic:
        - error: error_count > threshold
        - unresponsive: last_heartbeat > unresponsive_threshold
        - idle: last_heartbeat > idle_threshold
        - active: otherwise
        """
        now = datetime.utcnow()
        time_since_heartbeat = now - heartbeat.last_heartbeat

        if heartbeat.error_count >= self._error_threshold:
            return AgentStatus.ERROR
        elif time_since_heartbeat > self._unresponsive_threshold:
            return AgentStatus.UNRESPONSIVE
        elif time_since_heartbeat > self._idle_threshold:
            return AgentStatus.IDLE
        else:
            return AgentStatus.ACTIVE

    def get_all_agent_health(self) -> dict[str, AgentHeartbeat]:
        """
        Get health status for all known agents.

        Returns:
            Dict mapping agent_id to AgentHeartbeat
        """
        # Update status for all agents
        for agent_id, heartbeat in self._heartbeats.items():
            heartbeat.status = self._determine_status(heartbeat)

        return self._heartbeats.copy()

    async def _persist_heartbeat(self, heartbeat: AgentHeartbeat) -> None:
        """Persist heartbeat to Redis."""
        if not self._redis or not self._redis._client:
            return

        try:
            key = f"{HEARTBEAT_KEY_PREFIX}{heartbeat.agent_id}"

            # Store heartbeat data with TTL
            await self._redis._client.set(
                key,
                json.dumps(heartbeat.to_dict()),
                ex=120,  # 2 minute TTL
            )

            # Also store in agents health hash
            await self._redis._client.hset(
                HEALTH_AGENTS_KEY,
                heartbeat.agent_id,
                json.dumps(heartbeat.to_dict()),
            )
            await self._redis._client.expire(HEALTH_AGENTS_KEY, 120)

        except Exception as e:
            logger.error("failed_to_persist_heartbeat", error=str(e), agent_id=heartbeat.agent_id)

    async def load_from_redis(self) -> None:
        """Load heartbeat data from Redis."""
        if not self._redis or not self._redis._client:
            return

        try:
            # Get all heartbeat keys
            keys = await self._redis._client.keys(f"{HEARTBEAT_KEY_PREFIX}*")

            for key in keys:
                data = await self._redis._client.get(key)
                if data:
                    heartbeat_data = json.loads(data)
                    heartbeat = AgentHeartbeat.from_dict(heartbeat_data)
                    heartbeat.status = self._determine_status(heartbeat)
                    self._heartbeats[heartbeat.agent_id] = heartbeat

        except Exception as e:
            logger.error("failed_to_load_heartbeats_from_redis", error=str(e))

    async def get_persisted_agent_health(self) -> dict[str, dict]:
        """
        Get persisted agent health from Redis.

        Returns:
            Dict mapping agent_id to health data
        """
        if not self._redis or not self._redis._client:
            return {}

        try:
            health_data = await self._redis._client.hgetall(HEALTH_AGENTS_KEY)
            return {
                agent_id: json.loads(data)
                for agent_id, data in health_data.items()
            }
        except Exception as e:
            logger.error("failed_to_get_persisted_agent_health", error=str(e))
            return {}


class HeartbeatMixin:
    """
    Mixin class for agent bots to add heartbeat tracking.

    Add this to agent bot classes to enable health status tracking.
    """

    def _init_heartbeat(self) -> None:
        """Initialize heartbeat tracking fields."""
        self._last_heartbeat: datetime = datetime.utcnow()
        self._error_count: int = 0
        self._status: AgentStatus = AgentStatus.ACTIVE
        self._processing: bool = False
        # Only initialize _heartbeat_manager if not already set
        if not hasattr(self, '_heartbeat_manager') or self._heartbeat_manager is None:
            self._heartbeat_manager: Optional[HeartbeatManager] = None

    def set_heartbeat_manager(self, manager: HeartbeatManager) -> None:
        """Set the heartbeat manager for this agent."""
        self._heartbeat_manager = manager

    async def record_heartbeat(self, processing: bool = False) -> None:
        """Record a heartbeat for this agent."""
        self._last_heartbeat = datetime.utcnow()
        self._processing = processing

        if self._heartbeat_manager:
            await self._heartbeat_manager.record_heartbeat(
                agent_id=self.bot_id,
                agent_type=self.bot_type,
                processing=processing,
            )

    async def record_activity(self) -> None:
        """Record that this agent performed an activity."""
        self._last_heartbeat = datetime.utcnow()

        if self._heartbeat_manager:
            await self._heartbeat_manager.record_activity(self.bot_id)

    async def record_error(self, error_message: Optional[str] = None) -> None:
        """Record an error for this agent."""
        self._error_count += 1

        if self._heartbeat_manager:
            await self._heartbeat_manager.record_error(self.bot_id, error_message)

    def get_health_status(self) -> str:
        """
        Get actual agent health status.

        Returns:
            Status string: "active", "idle", "unresponsive", or "error"
        """
        now = datetime.utcnow()
        idle_threshold = timedelta(seconds=DEFAULT_IDLE_THRESHOLD_SECONDS)
        unresponsive_threshold = timedelta(seconds=DEFAULT_UNRESPONSIVE_THRESHOLD_SECONDS)

        if self._error_count >= DEFAULT_ERROR_THRESHOLD:
            return "error"
        elif now - self._last_heartbeat > unresponsive_threshold:
            return "unresponsive"
        elif now - self._last_heartbeat > idle_threshold:
            return "idle"
        return "active"

    def reset_error_count(self) -> None:
        """Reset error count after recovery."""
        self._error_count = 0
