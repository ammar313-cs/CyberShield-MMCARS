"""
Domain Events
Events raised when significant domain actions occur.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
from enum import Enum


class EventType(str, Enum):
    """Types of domain events."""

    THREAT_DETECTED = "threat_detected"
    THREAT_CONFIRMED = "threat_confirmed"
    THREAT_MITIGATED = "threat_mitigated"
    THREAT_ESCALATED = "threat_escalated"
    ATTACK_MITIGATED = "attack_mitigated"
    AGENT_RESPONSE = "agent_response"
    ACTION_EXECUTED = "action_executed"
    ACTION_FAILED = "action_failed"
    SYSTEM_ALERT = "system_alert"


@dataclass
class DomainEvent:
    """Base class for all domain events."""

    id: UUID
    event_type: EventType
    timestamp: datetime
    correlation_id: Optional[UUID] = None
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        event_type: EventType,
        correlation_id: Optional[UUID] = None,
        **kwargs,
    ) -> "DomainEvent":
        """Create a new domain event."""
        return cls(
            id=uuid4(),
            event_type=event_type,
            timestamp=datetime.utcnow(),
            correlation_id=correlation_id,
            **kwargs,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "metadata": self.metadata,
        }


@dataclass
class ThreatDetectedEvent(DomainEvent):
    """Event raised when a new threat is detected."""

    threat_id: UUID = field(default_factory=uuid4)
    source_ip: str = ""
    attack_type: str = ""
    severity: str = ""
    threat_score: float = 0.0
    detection_source: str = "ml_engine"
    target_ip: Optional[str] = None
    target_port: Optional[int] = None

    @classmethod
    def create(
        cls,
        threat_id: UUID,
        source_ip: str,
        attack_type: str,
        severity: str,
        threat_score: float,
        detection_source: str = "ml_engine",
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
    ) -> "ThreatDetectedEvent":
        """Create a threat detected event."""
        return cls(
            id=uuid4(),
            event_type=EventType.THREAT_DETECTED,
            timestamp=datetime.utcnow(),
            correlation_id=threat_id,
            threat_id=threat_id,
            source_ip=source_ip,
            attack_type=attack_type,
            severity=severity,
            threat_score=threat_score,
            detection_source=detection_source,
            target_ip=target_ip,
            target_port=target_port,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "threat_id": str(self.threat_id),
            "source_ip": self.source_ip,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "threat_score": self.threat_score,
            "detection_source": self.detection_source,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
        })
        return base


@dataclass
class ThreatConfirmedEvent(DomainEvent):
    """Event raised when a threat is confirmed."""

    threat_id: UUID = field(default_factory=uuid4)
    confirmed_by: str = ""
    updated_severity: Optional[str] = None
    confidence: float = 1.0

    @classmethod
    def create(
        cls,
        threat_id: UUID,
        confirmed_by: str,
        updated_severity: Optional[str] = None,
        confidence: float = 1.0,
    ) -> "ThreatConfirmedEvent":
        """Create a threat confirmed event."""
        return cls(
            id=uuid4(),
            event_type=EventType.THREAT_CONFIRMED,
            timestamp=datetime.utcnow(),
            correlation_id=threat_id,
            threat_id=threat_id,
            confirmed_by=confirmed_by,
            updated_severity=updated_severity,
            confidence=confidence,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "threat_id": str(self.threat_id),
            "confirmed_by": self.confirmed_by,
            "updated_severity": self.updated_severity,
            "confidence": self.confidence,
        })
        return base


@dataclass
class AttackMitigatedEvent(DomainEvent):
    """Event raised when an attack is mitigated."""

    threat_id: UUID = field(default_factory=uuid4)
    action_id: UUID = field(default_factory=uuid4)
    action_type: str = ""
    target: str = ""
    mitigation_duration: float = 0.0
    success: bool = True
    result_message: str = ""

    @classmethod
    def create(
        cls,
        threat_id: UUID,
        action_id: UUID,
        action_type: str,
        target: str,
        mitigation_duration: float,
        success: bool = True,
        result_message: str = "",
    ) -> "AttackMitigatedEvent":
        """Create an attack mitigated event."""
        return cls(
            id=uuid4(),
            event_type=EventType.ATTACK_MITIGATED,
            timestamp=datetime.utcnow(),
            correlation_id=threat_id,
            threat_id=threat_id,
            action_id=action_id,
            action_type=action_type,
            target=target,
            mitigation_duration=mitigation_duration,
            success=success,
            result_message=result_message,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "threat_id": str(self.threat_id),
            "action_id": str(self.action_id),
            "action_type": self.action_type,
            "target": self.target,
            "mitigation_duration": self.mitigation_duration,
            "success": self.success,
            "result_message": self.result_message,
        })
        return base


@dataclass
class AgentResponseEvent(DomainEvent):
    """Event raised when an agent responds to a threat."""

    agent_id: str = ""
    agent_type: str = ""
    threat_id: UUID = field(default_factory=uuid4)
    response_type: str = ""
    response_data: dict = field(default_factory=dict)
    processing_time_ms: float = 0.0

    @classmethod
    def create(
        cls,
        agent_id: str,
        agent_type: str,
        threat_id: UUID,
        response_type: str,
        response_data: dict,
        processing_time_ms: float = 0.0,
    ) -> "AgentResponseEvent":
        """Create an agent response event."""
        return cls(
            id=uuid4(),
            event_type=EventType.AGENT_RESPONSE,
            timestamp=datetime.utcnow(),
            correlation_id=threat_id,
            agent_id=agent_id,
            agent_type=agent_type,
            threat_id=threat_id,
            response_type=response_type,
            response_data=response_data,
            processing_time_ms=processing_time_ms,
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "threat_id": str(self.threat_id),
            "response_type": self.response_type,
            "response_data": self.response_data,
            "processing_time_ms": self.processing_time_ms,
        })
        return base


@dataclass
class SystemAlertEvent(DomainEvent):
    """Event for system-level alerts."""

    alert_level: str = "info"
    alert_message: str = ""
    source_component: str = ""
    affected_systems: list = field(default_factory=list)

    @classmethod
    def create(
        cls,
        alert_level: str,
        alert_message: str,
        source_component: str,
        affected_systems: Optional[list] = None,
    ) -> "SystemAlertEvent":
        """Create a system alert event."""
        return cls(
            id=uuid4(),
            event_type=EventType.SYSTEM_ALERT,
            timestamp=datetime.utcnow(),
            alert_level=alert_level,
            alert_message=alert_message,
            source_component=source_component,
            affected_systems=affected_systems or [],
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "alert_level": self.alert_level,
            "alert_message": self.alert_message,
            "source_component": self.source_component,
            "affected_systems": self.affected_systems,
        })
        return base
