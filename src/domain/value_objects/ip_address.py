"""
IP Address Value Object
Immutable representation of IP addresses with validation and utilities.
"""

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union
from enum import Enum


class IPVersion(str, Enum):
    """IP address version."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True)
class IPAddress:
    """
    Value object representing an IP address.

    Attributes:
        address: The IP address string
        version: IPv4 or IPv6
        is_private: Whether the address is private/internal
        is_loopback: Whether the address is loopback
    """

    address: str
    version: IPVersion
    is_private: bool
    is_loopback: bool
    is_multicast: bool
    is_reserved: bool

    def __post_init__(self) -> None:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(self.address)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {self.address}") from e

    @classmethod
    def from_string(cls, address: str) -> "IPAddress":
        """
        Create IPAddress from string representation.

        Args:
            address: IP address string (IPv4 or IPv6)

        Returns:
            IPAddress instance

        Raises:
            ValueError: If address is invalid
        """
        try:
            ip = ipaddress.ip_address(address)
            version = IPVersion.IPV4 if ip.version == 4 else IPVersion.IPV6

            return cls(
                address=str(ip),
                version=version,
                is_private=ip.is_private,
                is_loopback=ip.is_loopback,
                is_multicast=ip.is_multicast,
                is_reserved=ip.is_reserved,
            )
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {address}") from e

    @classmethod
    def from_bytes(cls, data: bytes) -> "IPAddress":
        """Create IPAddress from bytes representation."""
        ip = ipaddress.ip_address(data)
        return cls.from_string(str(ip))

    def is_internal(self) -> bool:
        """Check if address is internal (private, loopback, or reserved)."""
        return self.is_private or self.is_loopback or self.is_reserved

    def is_external(self) -> bool:
        """Check if address is external/public."""
        return not self.is_internal()

    def is_suspicious(self) -> bool:
        """
        Check if address exhibits suspicious characteristics.

        Reserved or multicast addresses in normal traffic may be suspicious.
        """
        return self.is_reserved or self.is_multicast

    def in_network(self, network: str) -> bool:
        """
        Check if address is in a given network.

        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            True if address is in the network
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
            ip = ipaddress.ip_address(self.address)
            return ip in net
        except ValueError:
            return False

    def get_network(self, prefix_length: Optional[int] = None) -> str:
        """
        Get the network address for this IP.

        Args:
            prefix_length: Network prefix length (default: 24 for IPv4, 64 for IPv6)

        Returns:
            Network address in CIDR notation
        """
        if prefix_length is None:
            prefix_length = 24 if self.version == IPVersion.IPV4 else 64

        ip = ipaddress.ip_address(self.address)
        if self.version == IPVersion.IPV4:
            network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        else:
            network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)

        return str(network)

    def __str__(self) -> str:
        """String representation."""
        return self.address

    def __hash__(self) -> int:
        """Hash for use in sets/dicts."""
        return hash(self.address)

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "address": self.address,
            "version": self.version.value,
            "is_private": self.is_private,
            "is_loopback": self.is_loopback,
            "is_multicast": self.is_multicast,
            "is_reserved": self.is_reserved,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IPAddress":
        """Create from dictionary representation."""
        return cls(
            address=data["address"],
            version=IPVersion(data["version"]),
            is_private=data["is_private"],
            is_loopback=data["is_loopback"],
            is_multicast=data["is_multicast"],
            is_reserved=data["is_reserved"],
        )


@dataclass(frozen=True)
class IPRange:
    """Value object representing a range of IP addresses."""

    network: str
    start_ip: str
    end_ip: str
    num_addresses: int

    @classmethod
    def from_cidr(cls, cidr: str) -> "IPRange":
        """Create IPRange from CIDR notation."""
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())

        if hosts:
            start_ip = str(hosts[0])
            end_ip = str(hosts[-1])
        else:
            start_ip = str(network.network_address)
            end_ip = str(network.broadcast_address)

        return cls(
            network=str(network),
            start_ip=start_ip,
            end_ip=end_ip,
            num_addresses=network.num_addresses,
        )

    def contains(self, ip: Union[str, IPAddress]) -> bool:
        """Check if IP address is in this range."""
        if isinstance(ip, IPAddress):
            ip = ip.address
        try:
            network = ipaddress.ip_network(self.network, strict=False)
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False
