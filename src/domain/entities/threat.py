"""
Threat Entity
Core domain entity representing a detected security threat.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
from enum import Enum

from src.domain.value_objects.threat_level import ThreatLevel, ThreatSeverity
from src.domain.value_objects.ip_address import IPAddress
from src.domain.value_objects.attack_signature import AttackSignature, AttackType


class ThreatStatus(str, Enum):
    """Status of a threat throughout its lifecycle."""

    DETECTED = "detected"
    ANALYZING = "analyzing"
    CONFIRMED = "confirmed"
    MITIGATING = "mitigating"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


@dataclass
class Threat:
    """
    Entity representing a detected security threat.

    This is the core aggregate root for threat management, containing
    all information about a detected attack and its handling status.
    """

    id: UUID
    source_ip: IPAddress
    target_ip: Optional[IPAddress]
    attack_signature: AttackSignature
    threat_level: ThreatLevel
    status: ThreatStatus
    detected_at: datetime
    updated_at: datetime
    target_port: Optional[int] = None
    packet_count: int = 0
    byte_count: int = 0
    connection_count: int = 0
    detection_source: str = "ml_engine"
    mitigated_at: Optional[datetime] = None
    mitigation_action: Optional[str] = None
    notes: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        source_ip: str,
        attack_signature: AttackSignature,
        threat_level: ThreatLevel,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        detection_source: str = "ml_engine",
    ) -> "Threat":
        """
        Factory method to create a new threat.

        Args:
            source_ip: Source IP address of the threat
            attack_signature: Detected attack pattern
            threat_level: Assessed threat level
            target_ip: Target IP address (if known)
            target_port: Target port (if known)
            detection_source: System that detected the threat

        Returns:
            New Threat instance
        """
        now = datetime.utcnow()
        return cls(
            id=uuid4(),
            source_ip=IPAddress.from_string(source_ip),
            target_ip=IPAddress.from_string(target_ip) if target_ip else None,
            attack_signature=attack_signature,
            threat_level=threat_level,
            status=ThreatStatus.DETECTED,
            detected_at=now,
            updated_at=now,
            target_port=target_port,
            detection_source=detection_source,
        )

    def analyze(self) -> None:
        """Transition threat to analyzing status."""
        if self.status != ThreatStatus.DETECTED:
            raise ValueError(f"Cannot analyze threat in {self.status} status")
        self.status = ThreatStatus.ANALYZING
        self.updated_at = datetime.utcnow()

    def confirm(self, updated_level: Optional[ThreatLevel] = None) -> None:
        """Confirm threat as real attack."""
        if self.status not in (ThreatStatus.DETECTED, ThreatStatus.ANALYZING):
            raise ValueError(f"Cannot confirm threat in {self.status} status")
        self.status = ThreatStatus.CONFIRMED
        if updated_level:
            self.threat_level = updated_level
        self.updated_at = datetime.utcnow()

    def start_mitigation(self, action: str) -> None:
        """Start mitigation process."""
        if self.status not in (ThreatStatus.CONFIRMED, ThreatStatus.DETECTED):
            raise ValueError(f"Cannot mitigate threat in {self.status} status")
        self.status = ThreatStatus.MITIGATING
        self.mitigation_action = action
        self.updated_at = datetime.utcnow()

    def complete_mitigation(self) -> None:
        """Mark threat as mitigated."""
        if self.status != ThreatStatus.MITIGATING:
            raise ValueError(f"Cannot complete mitigation in {self.status} status")
        self.status = ThreatStatus.MITIGATED
        self.mitigated_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def mark_false_positive(self, reason: str) -> None:
        """Mark threat as false positive."""
        self.status = ThreatStatus.FALSE_POSITIVE
        self.add_note(f"Marked as false positive: {reason}")
        self.updated_at = datetime.utcnow()

    def escalate(self, reason: str) -> None:
        """Escalate threat for human review."""
        self.status = ThreatStatus.ESCALATED
        self.add_note(f"Escalated: {reason}")
        self.updated_at = datetime.utcnow()

    def update_metrics(
        self,
        packets: int = 0,
        bytes_count: int = 0,
        connections: int = 0,
    ) -> None:
        """Update traffic metrics."""
        self.packet_count += packets
        self.byte_count += bytes_count
        self.connection_count += connections
        self.updated_at = datetime.utcnow()

    def add_note(self, note: str) -> None:
        """Add a note to the threat."""
        timestamp = datetime.utcnow().isoformat()
        self.notes.append(f"[{timestamp}] {note}")
        self.updated_at = datetime.utcnow()

    def update_threat_level(self, new_level: ThreatLevel) -> None:
        """Update the threat level assessment."""
        self.threat_level = new_level
        self.updated_at = datetime.utcnow()

    @property
    def attack_type(self) -> AttackType:
        """Get the attack type from signature."""
        return self.attack_signature.attack_type

    @property
    def severity(self) -> ThreatSeverity:
        """Get the severity from threat level."""
        return self.threat_level.severity

    @property
    def is_active(self) -> bool:
        """Check if threat is still active (not mitigated or false positive)."""
        return self.status not in (
            ThreatStatus.MITIGATED,
            ThreatStatus.FALSE_POSITIVE,
        )

    @property
    def requires_action(self) -> bool:
        """Check if threat requires immediate action."""
        return (
            self.is_active
            and self.threat_level.requires_immediate_response()
            and self.status != ThreatStatus.MITIGATING
        )

    @property
    def duration_seconds(self) -> float:
        """Get threat duration in seconds."""
        end_time = self.mitigated_at or datetime.utcnow()
        return (end_time - self.detected_at).total_seconds()

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "source_ip": self.source_ip.to_dict(),
            "target_ip": self.target_ip.to_dict() if self.target_ip else None,
            "attack_signature": self.attack_signature.to_dict(),
            "threat_level": self.threat_level.to_dict(),
            "status": self.status.value,
            "detected_at": self.detected_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "target_port": self.target_port,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "connection_count": self.connection_count,
            "detection_source": self.detection_source,
            "mitigated_at": self.mitigated_at.isoformat() if self.mitigated_at else None,
            "mitigation_action": self.mitigation_action,
            "notes": self.notes,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Threat":
        """Create from dictionary representation."""
        return cls(
            id=UUID(data["id"]),
            source_ip=IPAddress.from_dict(data["source_ip"]),
            target_ip=IPAddress.from_dict(data["target_ip"]) if data["target_ip"] else None,
            attack_signature=AttackSignature.from_dict(data["attack_signature"]),
            threat_level=ThreatLevel.from_dict(data["threat_level"]),
            status=ThreatStatus(data["status"]),
            detected_at=datetime.fromisoformat(data["detected_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            target_port=data.get("target_port"),
            packet_count=data.get("packet_count", 0),
            byte_count=data.get("byte_count", 0),
            connection_count=data.get("connection_count", 0),
            detection_source=data.get("detection_source", "ml_engine"),
            mitigated_at=(
                datetime.fromisoformat(data["mitigated_at"])
                if data.get("mitigated_at")
                else None
            ),
            mitigation_action=data.get("mitigation_action"),
            notes=data.get("notes", []),
            metadata=data.get("metadata", {}),
        )

    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Equality based on ID."""
        if not isinstance(other, Threat):
            return False
        return self.id == other.id
