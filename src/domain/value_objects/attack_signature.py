"""
Attack Signature Value Object
Immutable representation of attack pattern signatures.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from datetime import datetime
import hashlib
import json


class AttackType(str, Enum):
    """Types of network attacks."""

    # Volumetric attacks
    DDOS = "ddos"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    HTTP_FLOOD = "http_flood"

    # Reconnaissance attacks
    PORT_SCAN = "port_scan"
    NETWORK_SCAN = "network_scan"
    SERVICE_PROBE = "service_probe"

    # Protocol attacks
    SLOWLORIS = "slowloris"
    SLOW_POST = "slow_post"
    PING_OF_DEATH = "ping_of_death"
    TEARDROP = "teardrop"

    # Spoofing attacks
    IP_SPOOFING = "ip_spoofing"
    ARP_SPOOFING = "arp_spoofing"
    DNS_SPOOFING = "dns_spoofing"

    # Application-layer attacks
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    CREDENTIAL_STUFFING = "credential_stuffing"

    # Other
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


class AttackProtocol(str, Enum):
    """Network protocols involved in attacks."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AttackSignature:
    """
    Value object representing an attack signature/pattern.

    Attributes:
        attack_type: Type of attack detected
        protocol: Network protocol involved
        pattern_hash: Unique hash identifying this pattern
        indicators: List of indicator patterns
        description: Human-readable description
        severity_weight: Weight for severity calculation (0.0 - 1.0)
        first_seen: When this signature was first observed
    """

    attack_type: AttackType
    protocol: AttackProtocol
    pattern_hash: str
    indicators: tuple[str, ...]
    description: str
    severity_weight: float
    first_seen: datetime = field(default_factory=datetime.utcnow)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate signature values."""
        if not 0.0 <= self.severity_weight <= 1.0:
            raise ValueError(
                f"Severity weight must be between 0.0 and 1.0, got {self.severity_weight}"
            )

    @classmethod
    def create(
        cls,
        attack_type: AttackType,
        protocol: AttackProtocol,
        indicators: list[str],
        description: str,
        severity_weight: float = 0.5,
        metadata: Optional[dict] = None,
    ) -> "AttackSignature":
        """
        Create a new attack signature.

        Args:
            attack_type: Type of attack
            protocol: Protocol involved
            indicators: List of indicator patterns
            description: Human-readable description
            severity_weight: Severity weight (0.0 - 1.0)
            metadata: Additional metadata

        Returns:
            AttackSignature instance
        """
        # Generate pattern hash from key attributes
        hash_input = json.dumps(
            {
                "type": attack_type.value,
                "protocol": protocol.value,
                "indicators": sorted(indicators),
            },
            sort_keys=True,
        )
        pattern_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        return cls(
            attack_type=attack_type,
            protocol=protocol,
            pattern_hash=pattern_hash,
            indicators=tuple(indicators),
            description=description,
            severity_weight=severity_weight,
            first_seen=datetime.utcnow(),
            metadata=metadata or {},
        )

    @classmethod
    def ddos_signature(
        cls,
        protocol: AttackProtocol = AttackProtocol.TCP,
        indicators: Optional[list[str]] = None,
    ) -> "AttackSignature":
        """Create a DDoS attack signature."""
        default_indicators = [
            "high_packet_rate",
            "multiple_sources",
            "traffic_spike",
        ]
        return cls.create(
            attack_type=AttackType.DDOS,
            protocol=protocol,
            indicators=indicators or default_indicators,
            description="Distributed Denial of Service attack detected",
            severity_weight=0.9,
        )

    @classmethod
    def syn_flood_signature(cls) -> "AttackSignature":
        """Create a SYN flood signature."""
        return cls.create(
            attack_type=AttackType.SYN_FLOOD,
            protocol=AttackProtocol.TCP,
            indicators=[
                "high_syn_rate",
                "incomplete_handshakes",
                "syn_ack_ratio_abnormal",
            ],
            description="TCP SYN flood attack detected",
            severity_weight=0.85,
        )

    @classmethod
    def port_scan_signature(cls) -> "AttackSignature":
        """Create a port scan signature."""
        return cls.create(
            attack_type=AttackType.PORT_SCAN,
            protocol=AttackProtocol.TCP,
            indicators=[
                "sequential_ports",
                "single_source",
                "short_connections",
            ],
            description="Port scanning activity detected",
            severity_weight=0.6,
        )

    @classmethod
    def slowloris_signature(cls) -> "AttackSignature":
        """Create a Slowloris signature."""
        return cls.create(
            attack_type=AttackType.SLOWLORIS,
            protocol=AttackProtocol.HTTP,
            indicators=[
                "slow_headers",
                "incomplete_requests",
                "long_connection_duration",
            ],
            description="Slowloris slow-rate attack detected",
            severity_weight=0.7,
        )

    def matches(self, other: "AttackSignature") -> bool:
        """Check if two signatures match."""
        return self.pattern_hash == other.pattern_hash

    def is_volumetric(self) -> bool:
        """Check if this is a volumetric attack."""
        return self.attack_type in (
            AttackType.DDOS,
            AttackType.SYN_FLOOD,
            AttackType.UDP_FLOOD,
            AttackType.ICMP_FLOOD,
            AttackType.HTTP_FLOOD,
        )

    def is_reconnaissance(self) -> bool:
        """Check if this is a reconnaissance attack."""
        return self.attack_type in (
            AttackType.PORT_SCAN,
            AttackType.NETWORK_SCAN,
            AttackType.SERVICE_PROBE,
        )

    def __hash__(self) -> int:
        """Hash based on pattern hash."""
        return hash(self.pattern_hash)

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "attack_type": self.attack_type.value,
            "protocol": self.protocol.value,
            "pattern_hash": self.pattern_hash,
            "indicators": list(self.indicators),
            "description": self.description,
            "severity_weight": self.severity_weight,
            "first_seen": self.first_seen.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackSignature":
        """Create from dictionary representation."""
        return cls(
            attack_type=AttackType(data["attack_type"]),
            protocol=AttackProtocol(data["protocol"]),
            pattern_hash=data["pattern_hash"],
            indicators=tuple(data["indicators"]),
            description=data["description"],
            severity_weight=data["severity_weight"],
            first_seen=datetime.fromisoformat(data["first_seen"]),
            metadata=data.get("metadata", {}),
        )
