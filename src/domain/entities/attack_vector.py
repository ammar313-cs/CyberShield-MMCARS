"""
Attack Vector Entity
Represents a specific attack method and its characteristics.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
from enum import Enum

from src.domain.value_objects.attack_signature import AttackType, AttackProtocol


class VectorCategory(str, Enum):
    """Categories of attack vectors."""

    VOLUMETRIC = "volumetric"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    RECONNAISSANCE = "reconnaissance"
    EVASION = "evasion"


@dataclass
class AttackVector:
    """
    Entity representing an attack vector.

    An attack vector describes a specific method of attack, including
    its characteristics, detection patterns, and response strategies.
    """

    id: UUID
    name: str
    attack_type: AttackType
    protocol: AttackProtocol
    category: VectorCategory
    description: str
    created_at: datetime
    updated_at: datetime
    detection_patterns: list[str] = field(default_factory=list)
    response_strategies: list[str] = field(default_factory=list)
    severity_base: float = 0.5
    is_active: bool = True
    occurrence_count: int = 0
    last_seen: Optional[datetime] = None
    effectiveness_score: float = 0.0
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        name: str,
        attack_type: AttackType,
        protocol: AttackProtocol,
        category: VectorCategory,
        description: str,
        detection_patterns: Optional[list[str]] = None,
        response_strategies: Optional[list[str]] = None,
        severity_base: float = 0.5,
    ) -> "AttackVector":
        """
        Factory method to create a new attack vector.

        Args:
            name: Human-readable name
            attack_type: Type of attack
            protocol: Network protocol
            category: Vector category
            description: Detailed description
            detection_patterns: Patterns for detection
            response_strategies: Response strategies
            severity_base: Base severity (0.0 - 1.0)

        Returns:
            New AttackVector instance
        """
        now = datetime.utcnow()
        return cls(
            id=uuid4(),
            name=name,
            attack_type=attack_type,
            protocol=protocol,
            category=category,
            description=description,
            created_at=now,
            updated_at=now,
            detection_patterns=detection_patterns or [],
            response_strategies=response_strategies or [],
            severity_base=severity_base,
        )

    @classmethod
    def ddos_vector(cls) -> "AttackVector":
        """Create a DDoS attack vector."""
        return cls.create(
            name="Distributed Denial of Service",
            attack_type=AttackType.DDOS,
            protocol=AttackProtocol.TCP,
            category=VectorCategory.VOLUMETRIC,
            description="High-volume traffic flood from multiple sources to overwhelm target",
            detection_patterns=[
                "traffic_volume_spike",
                "multiple_source_ips",
                "abnormal_packet_rate",
                "geographic_distribution",
            ],
            response_strategies=[
                "rate_limiting",
                "ip_blacklisting",
                "traffic_scrubbing",
                "upstream_filtering",
            ],
            severity_base=0.9,
        )

    @classmethod
    def syn_flood_vector(cls) -> "AttackVector":
        """Create a SYN flood attack vector."""
        return cls.create(
            name="TCP SYN Flood",
            attack_type=AttackType.SYN_FLOOD,
            protocol=AttackProtocol.TCP,
            category=VectorCategory.PROTOCOL,
            description="TCP SYN packet flood exploiting three-way handshake",
            detection_patterns=[
                "high_syn_rate",
                "incomplete_handshakes",
                "syn_ack_ratio",
                "half_open_connections",
            ],
            response_strategies=[
                "syn_cookies",
                "connection_limiting",
                "timeout_reduction",
                "rate_limiting",
            ],
            severity_base=0.85,
        )

    @classmethod
    def port_scan_vector(cls) -> "AttackVector":
        """Create a port scan attack vector."""
        return cls.create(
            name="Port Scanning",
            attack_type=AttackType.PORT_SCAN,
            protocol=AttackProtocol.TCP,
            category=VectorCategory.RECONNAISSANCE,
            description="Sequential probing of ports to discover services",
            detection_patterns=[
                "sequential_port_access",
                "single_source_multiple_ports",
                "short_connections",
                "no_data_transfer",
            ],
            response_strategies=[
                "temporary_ip_block",
                "honeypot_redirect",
                "alert_generation",
                "traffic_analysis",
            ],
            severity_base=0.6,
        )

    @classmethod
    def slowloris_vector(cls) -> "AttackVector":
        """Create a Slowloris attack vector."""
        return cls.create(
            name="Slowloris",
            attack_type=AttackType.SLOWLORIS,
            protocol=AttackProtocol.HTTP,
            category=VectorCategory.APPLICATION,
            description="Slow HTTP attack maintaining partial connections",
            detection_patterns=[
                "slow_header_transmission",
                "incomplete_requests",
                "long_connection_duration",
                "low_bandwidth_usage",
            ],
            response_strategies=[
                "connection_timeout_reduction",
                "max_connections_limit",
                "request_rate_limiting",
                "ip_blocking",
            ],
            severity_base=0.7,
        )

    def record_occurrence(self) -> None:
        """Record a new occurrence of this attack vector."""
        self.occurrence_count += 1
        self.last_seen = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def add_detection_pattern(self, pattern: str) -> None:
        """Add a new detection pattern."""
        if pattern not in self.detection_patterns:
            self.detection_patterns.append(pattern)
            self.updated_at = datetime.utcnow()

    def add_response_strategy(self, strategy: str) -> None:
        """Add a new response strategy."""
        if strategy not in self.response_strategies:
            self.response_strategies.append(strategy)
            self.updated_at = datetime.utcnow()

    def update_effectiveness(self, score: float) -> None:
        """Update effectiveness score based on mitigation success."""
        if not 0.0 <= score <= 1.0:
            raise ValueError("Effectiveness score must be between 0.0 and 1.0")
        # Exponential moving average
        alpha = 0.3
        self.effectiveness_score = alpha * score + (1 - alpha) * self.effectiveness_score
        self.updated_at = datetime.utcnow()

    def deactivate(self) -> None:
        """Deactivate this attack vector."""
        self.is_active = False
        self.updated_at = datetime.utcnow()

    def activate(self) -> None:
        """Activate this attack vector."""
        self.is_active = True
        self.updated_at = datetime.utcnow()

    @property
    def is_volumetric(self) -> bool:
        """Check if this is a volumetric attack."""
        return self.category == VectorCategory.VOLUMETRIC

    @property
    def is_reconnaissance(self) -> bool:
        """Check if this is a reconnaissance attack."""
        return self.category == VectorCategory.RECONNAISSANCE

    @property
    def calculated_severity(self) -> float:
        """Calculate current severity based on occurrence and effectiveness."""
        # Increase severity with more occurrences
        occurrence_factor = min(1.0, self.occurrence_count / 100)
        # Adjust by effectiveness (higher effectiveness = more dangerous)
        return self.severity_base * (0.7 + 0.3 * occurrence_factor) * (0.8 + 0.2 * self.effectiveness_score)

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "attack_type": self.attack_type.value,
            "protocol": self.protocol.value,
            "category": self.category.value,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "detection_patterns": self.detection_patterns,
            "response_strategies": self.response_strategies,
            "severity_base": self.severity_base,
            "is_active": self.is_active,
            "occurrence_count": self.occurrence_count,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "effectiveness_score": self.effectiveness_score,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackVector":
        """Create from dictionary representation."""
        return cls(
            id=UUID(data["id"]),
            name=data["name"],
            attack_type=AttackType(data["attack_type"]),
            protocol=AttackProtocol(data["protocol"]),
            category=VectorCategory(data["category"]),
            description=data["description"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            detection_patterns=data.get("detection_patterns", []),
            response_strategies=data.get("response_strategies", []),
            severity_base=data.get("severity_base", 0.5),
            is_active=data.get("is_active", True),
            occurrence_count=data.get("occurrence_count", 0),
            last_seen=(
                datetime.fromisoformat(data["last_seen"])
                if data.get("last_seen")
                else None
            ),
            effectiveness_score=data.get("effectiveness_score", 0.0),
            metadata=data.get("metadata", {}),
        )

    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Equality based on ID."""
        if not isinstance(other, AttackVector):
            return False
        return self.id == other.id
