"""
Traffic Event Entity
Represents a network traffic event for analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from src.domain.value_objects.ip_address import IPAddress
from src.domain.value_objects.attack_signature import AttackProtocol


@dataclass
class TrafficEvent:
    """
    Entity representing a network traffic event.

    Captures raw traffic data for analysis by the detection engine.
    """

    id: UUID
    timestamp: datetime
    source_ip: IPAddress
    destination_ip: IPAddress
    source_port: int
    destination_port: int
    protocol: AttackProtocol
    packet_size: int
    flags: list[str] = field(default_factory=list)
    payload_size: int = 0
    ttl: int = 64
    window_size: int = 0
    sequence_number: Optional[int] = None
    acknowledgment_number: Optional[int] = None
    is_fragmented: bool = False
    fragment_offset: int = 0
    header_length: int = 0
    processed: bool = False
    threat_id: Optional[UUID] = None
    metadata: dict = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: AttackProtocol,
        packet_size: int,
        flags: Optional[list[str]] = None,
        payload_size: int = 0,
        ttl: int = 64,
    ) -> "TrafficEvent":
        """
        Factory method to create a traffic event.

        Args:
            source_ip: Source IP address
            destination_ip: Destination IP address
            source_port: Source port number
            destination_port: Destination port number
            protocol: Network protocol
            packet_size: Total packet size in bytes
            flags: TCP/IP flags
            payload_size: Payload size in bytes
            ttl: Time to live

        Returns:
            New TrafficEvent instance
        """
        return cls(
            id=uuid4(),
            timestamp=datetime.utcnow(),
            source_ip=IPAddress.from_string(source_ip),
            destination_ip=IPAddress.from_string(destination_ip),
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_size=packet_size,
            flags=flags or [],
            payload_size=payload_size,
            ttl=ttl,
        )

    @classmethod
    def from_packet(cls, packet_data: dict) -> "TrafficEvent":
        """
        Create from raw packet data dictionary.

        Args:
            packet_data: Dictionary with packet information

        Returns:
            New TrafficEvent instance
        """
        protocol_map = {
            6: AttackProtocol.TCP,
            17: AttackProtocol.UDP,
            1: AttackProtocol.ICMP,
        }

        protocol = protocol_map.get(
            packet_data.get("protocol_num", 0),
            AttackProtocol.UNKNOWN,
        )

        return cls(
            id=uuid4(),
            timestamp=datetime.utcnow(),
            source_ip=IPAddress.from_string(packet_data["src_ip"]),
            destination_ip=IPAddress.from_string(packet_data["dst_ip"]),
            source_port=packet_data.get("src_port", 0),
            destination_port=packet_data.get("dst_port", 0),
            protocol=protocol,
            packet_size=packet_data.get("packet_size", 0),
            flags=packet_data.get("flags", []),
            payload_size=packet_data.get("payload_size", 0),
            ttl=packet_data.get("ttl", 64),
            window_size=packet_data.get("window_size", 0),
            sequence_number=packet_data.get("seq_num"),
            acknowledgment_number=packet_data.get("ack_num"),
            is_fragmented=packet_data.get("is_fragmented", False),
            fragment_offset=packet_data.get("fragment_offset", 0),
            header_length=packet_data.get("header_length", 0),
            metadata=packet_data.get("metadata", {}),
        )

    def mark_processed(self, threat_id: Optional[UUID] = None) -> None:
        """Mark event as processed, optionally linking to a threat."""
        self.processed = True
        self.threat_id = threat_id

    @property
    def is_tcp(self) -> bool:
        """Check if this is a TCP event."""
        return self.protocol == AttackProtocol.TCP

    @property
    def is_udp(self) -> bool:
        """Check if this is a UDP event."""
        return self.protocol == AttackProtocol.UDP

    @property
    def is_icmp(self) -> bool:
        """Check if this is an ICMP event."""
        return self.protocol == AttackProtocol.ICMP

    @property
    def has_syn_flag(self) -> bool:
        """Check if SYN flag is set."""
        return "SYN" in self.flags or "S" in self.flags

    @property
    def has_ack_flag(self) -> bool:
        """Check if ACK flag is set."""
        return "ACK" in self.flags or "A" in self.flags

    @property
    def has_fin_flag(self) -> bool:
        """Check if FIN flag is set."""
        return "FIN" in self.flags or "F" in self.flags

    @property
    def has_rst_flag(self) -> bool:
        """Check if RST flag is set."""
        return "RST" in self.flags or "R" in self.flags

    @property
    def is_syn_only(self) -> bool:
        """Check if only SYN flag is set (potential SYN flood)."""
        return self.has_syn_flag and not self.has_ack_flag

    @property
    def source_ip_str(self) -> str:
        """Get source IP as string."""
        return str(self.source_ip)

    @property
    def destination_ip_str(self) -> str:
        """Get destination IP as string."""
        return str(self.destination_ip)

    @property
    def flow_tuple(self) -> tuple:
        """Get flow tuple for grouping related packets."""
        return (
            self.source_ip_str,
            self.destination_ip_str,
            self.source_port,
            self.destination_port,
            self.protocol.value,
        )

    def to_feature_vector(self) -> list[float]:
        """
        Convert to feature vector for ML models.

        Returns:
            List of numeric features
        """
        return [
            self.packet_size,
            self.payload_size,
            self.source_port,
            self.destination_port,
            self.ttl,
            self.window_size,
            self.header_length,
            1.0 if self.has_syn_flag else 0.0,
            1.0 if self.has_ack_flag else 0.0,
            1.0 if self.has_fin_flag else 0.0,
            1.0 if self.has_rst_flag else 0.0,
            1.0 if self.is_fragmented else 0.0,
            1.0 if self.source_ip.is_private else 0.0,
            1.0 if self.destination_ip.is_private else 0.0,
        ]

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip.to_dict(),
            "destination_ip": self.destination_ip.to_dict(),
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol.value,
            "packet_size": self.packet_size,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "ttl": self.ttl,
            "window_size": self.window_size,
            "sequence_number": self.sequence_number,
            "acknowledgment_number": self.acknowledgment_number,
            "is_fragmented": self.is_fragmented,
            "fragment_offset": self.fragment_offset,
            "header_length": self.header_length,
            "processed": self.processed,
            "threat_id": str(self.threat_id) if self.threat_id else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TrafficEvent":
        """Create from dictionary representation."""
        return cls(
            id=UUID(data["id"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_ip=IPAddress.from_dict(data["source_ip"]),
            destination_ip=IPAddress.from_dict(data["destination_ip"]),
            source_port=data["source_port"],
            destination_port=data["destination_port"],
            protocol=AttackProtocol(data["protocol"]),
            packet_size=data["packet_size"],
            flags=data.get("flags", []),
            payload_size=data.get("payload_size", 0),
            ttl=data.get("ttl", 64),
            window_size=data.get("window_size", 0),
            sequence_number=data.get("sequence_number"),
            acknowledgment_number=data.get("acknowledgment_number"),
            is_fragmented=data.get("is_fragmented", False),
            fragment_offset=data.get("fragment_offset", 0),
            header_length=data.get("header_length", 0),
            processed=data.get("processed", False),
            threat_id=UUID(data["threat_id"]) if data.get("threat_id") else None,
            metadata=data.get("metadata", {}),
        )

    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Equality based on ID."""
        if not isinstance(other, TrafficEvent):
            return False
        return self.id == other.id
