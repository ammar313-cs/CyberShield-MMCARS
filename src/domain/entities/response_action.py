"""
Response Action Entity
Represents actions taken in response to threats.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
from enum import Enum


class ActionType(str, Enum):
    """Types of response actions."""

    BLOCK_IP = "block_ip"
    RATE_LIMIT = "rate_limit"
    DROP_CONNECTION = "drop_connection"
    REDIRECT_HONEYPOT = "redirect_honeypot"
    NOTIFY_UPSTREAM = "notify_upstream"
    GENERATE_ALERT = "generate_alert"
    LOG_EVENT = "log_event"
    ESCALATE = "escalate"
    WHITELIST = "whitelist"
    CUSTOM = "custom"


class ActionStatus(str, Enum):
    """Status of a response action."""

    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


class ActionPriority(str, Enum):
    """Priority levels for actions."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ResponseAction:
    """
    Entity representing a response action to a threat.

    Actions are commands executed by the mitigation system to
    counter detected threats.
    """

    id: UUID
    threat_id: UUID
    action_type: ActionType
    status: ActionStatus
    priority: ActionPriority
    created_at: datetime
    updated_at: datetime
    target: str
    parameters: dict = field(default_factory=dict)
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    result: Optional[str] = None
    error_message: Optional[str] = None
    rollback_action: Optional["ResponseAction"] = None
    agent_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        threat_id: UUID,
        action_type: ActionType,
        target: str,
        priority: ActionPriority = ActionPriority.NORMAL,
        parameters: Optional[dict] = None,
        expires_in_seconds: Optional[int] = None,
        agent_id: Optional[str] = None,
    ) -> "ResponseAction":
        """
        Factory method to create a new response action.

        Args:
            threat_id: ID of the associated threat
            action_type: Type of action to take
            target: Target of the action (IP, port, etc.)
            priority: Action priority
            parameters: Additional parameters
            expires_in_seconds: Action expiration time
            agent_id: ID of agent initiating action

        Returns:
            New ResponseAction instance
        """
        now = datetime.utcnow()
        expires_at = None
        if expires_in_seconds:
            from datetime import timedelta
            expires_at = now + timedelta(seconds=expires_in_seconds)

        return cls(
            id=uuid4(),
            threat_id=threat_id,
            action_type=action_type,
            status=ActionStatus.PENDING,
            priority=priority,
            created_at=now,
            updated_at=now,
            target=target,
            parameters=parameters or {},
            expires_at=expires_at,
            agent_id=agent_id,
        )

    @classmethod
    def block_ip(
        cls,
        threat_id: UUID,
        ip_address: str,
        duration_seconds: int = 3600,
        priority: ActionPriority = ActionPriority.HIGH,
    ) -> "ResponseAction":
        """Create an IP blocking action."""
        return cls.create(
            threat_id=threat_id,
            action_type=ActionType.BLOCK_IP,
            target=ip_address,
            priority=priority,
            parameters={"duration": duration_seconds},
            expires_in_seconds=duration_seconds,
        )

    @classmethod
    def rate_limit(
        cls,
        threat_id: UUID,
        ip_address: str,
        requests_per_second: int = 10,
        duration_seconds: int = 300,
    ) -> "ResponseAction":
        """Create a rate limiting action."""
        return cls.create(
            threat_id=threat_id,
            action_type=ActionType.RATE_LIMIT,
            target=ip_address,
            priority=ActionPriority.NORMAL,
            parameters={
                "rate_limit": requests_per_second,
                "duration": duration_seconds,
            },
            expires_in_seconds=duration_seconds,
        )

    @classmethod
    def drop_connection(
        cls,
        threat_id: UUID,
        connection_id: str,
        priority: ActionPriority = ActionPriority.HIGH,
    ) -> "ResponseAction":
        """Create a connection drop action."""
        return cls.create(
            threat_id=threat_id,
            action_type=ActionType.DROP_CONNECTION,
            target=connection_id,
            priority=priority,
        )

    @classmethod
    def generate_alert(
        cls,
        threat_id: UUID,
        alert_message: str,
        severity: str = "high",
    ) -> "ResponseAction":
        """Create an alert generation action."""
        return cls.create(
            threat_id=threat_id,
            action_type=ActionType.GENERATE_ALERT,
            target="alert_system",
            priority=ActionPriority.NORMAL,
            parameters={"message": alert_message, "severity": severity},
        )

    def start_execution(self) -> None:
        """Mark action as executing."""
        if self.status != ActionStatus.PENDING:
            raise ValueError(f"Cannot start execution from {self.status} status")
        self.status = ActionStatus.EXECUTING
        self.executed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def complete(self, result: Optional[str] = None) -> None:
        """Mark action as completed."""
        if self.status != ActionStatus.EXECUTING:
            raise ValueError(f"Cannot complete from {self.status} status")
        self.status = ActionStatus.COMPLETED
        self.result = result
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def fail(self, error_message: str) -> None:
        """Mark action as failed."""
        self.status = ActionStatus.FAILED
        self.error_message = error_message
        self.updated_at = datetime.utcnow()

    def retry(self) -> bool:
        """
        Attempt to retry the action.

        Returns:
            True if retry is allowed, False if max retries exceeded
        """
        if self.retry_count >= self.max_retries:
            return False
        self.retry_count += 1
        self.status = ActionStatus.PENDING
        self.error_message = None
        self.updated_at = datetime.utcnow()
        return True

    def rollback(self) -> None:
        """Mark action as rolled back."""
        self.status = ActionStatus.ROLLED_BACK
        self.updated_at = datetime.utcnow()

    def check_expiration(self) -> bool:
        """
        Check if action has expired.

        Returns:
            True if expired, False otherwise
        """
        if self.expires_at and datetime.utcnow() > self.expires_at:
            self.status = ActionStatus.EXPIRED
            self.updated_at = datetime.utcnow()
            return True
        return False

    @property
    def is_pending(self) -> bool:
        """Check if action is pending."""
        return self.status == ActionStatus.PENDING

    @property
    def is_executing(self) -> bool:
        """Check if action is executing."""
        return self.status == ActionStatus.EXECUTING

    @property
    def is_completed(self) -> bool:
        """Check if action is completed."""
        return self.status == ActionStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        """Check if action has failed."""
        return self.status == ActionStatus.FAILED

    @property
    def can_retry(self) -> bool:
        """Check if action can be retried."""
        return self.is_failed and self.retry_count < self.max_retries

    @property
    def execution_duration(self) -> Optional[float]:
        """Get execution duration in seconds."""
        if self.executed_at and self.completed_at:
            return (self.completed_at - self.executed_at).total_seconds()
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "threat_id": str(self.threat_id),
            "action_type": self.action_type.value,
            "status": self.status.value,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "target": self.target,
            "parameters": self.parameters,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "result": self.result,
            "error_message": self.error_message,
            "agent_id": self.agent_id,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ResponseAction":
        """Create from dictionary representation."""
        return cls(
            id=UUID(data["id"]),
            threat_id=UUID(data["threat_id"]),
            action_type=ActionType(data["action_type"]),
            status=ActionStatus(data["status"]),
            priority=ActionPriority(data["priority"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            target=data["target"],
            parameters=data.get("parameters", {}),
            executed_at=(
                datetime.fromisoformat(data["executed_at"])
                if data.get("executed_at")
                else None
            ),
            completed_at=(
                datetime.fromisoformat(data["completed_at"])
                if data.get("completed_at")
                else None
            ),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            result=data.get("result"),
            error_message=data.get("error_message"),
            agent_id=data.get("agent_id"),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 3),
            metadata=data.get("metadata", {}),
        )

    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Equality based on ID."""
        if not isinstance(other, ResponseAction):
            return False
        return self.id == other.id
