"""
Reverse Proxy Configuration

Configuration for the CyberShield reverse proxy gateway.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class InspectionMode(str, Enum):
    """Traffic inspection modes."""

    PASSIVE = "passive"  # Log only, no blocking
    ACTIVE = "active"  # Analyze and block threats
    STRICT = "strict"  # Block suspicious + threats
    LEARNING = "learning"  # Collect data for ML training


class LoadBalanceStrategy(str, Enum):
    """Load balancing strategies for upstream servers."""

    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    RANDOM = "random"
    IP_HASH = "ip_hash"
    WEIGHTED = "weighted"


@dataclass
class UpstreamServer:
    """Configuration for an upstream server."""

    host: str
    port: int
    weight: int = 1
    max_connections: int = 100
    health_check_path: str = "/health"
    timeout_seconds: float = 30.0
    ssl: bool = False

    @property
    def url(self) -> str:
        """Get the full URL for this upstream server."""
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.host}:{self.port}"


@dataclass
class ProxyConfig:
    """
    Configuration for the CyberShield Reverse Proxy Gateway.

    Attributes:
        listen_host: Host to bind the proxy server to
        listen_port: Port to listen on for incoming traffic
        upstream_servers: List of upstream servers to forward traffic to
        inspection_mode: How to handle traffic inspection
        enable_ssl: Whether to enable SSL/TLS termination
        ssl_cert_path: Path to SSL certificate
        ssl_key_path: Path to SSL private key
        request_timeout: Timeout for upstream requests
        max_request_size: Maximum allowed request body size
        blocked_ips: Set of IPs to always block
        allowed_ips: Set of IPs to always allow (bypass inspection)
        rate_limit_requests: Max requests per window
        rate_limit_window: Window size in seconds
        enable_websocket: Enable WebSocket proxying
        buffer_size: Buffer size for streaming responses
        preserve_host: Preserve original Host header
        add_headers: Headers to add to forwarded requests
        remove_headers: Headers to remove from forwarded requests
    """

    # Server binding
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080

    # Upstream configuration
    upstream_servers: List[UpstreamServer] = field(default_factory=list)
    load_balance_strategy: LoadBalanceStrategy = LoadBalanceStrategy.ROUND_ROBIN

    # Inspection settings
    inspection_mode: InspectionMode = InspectionMode.ACTIVE
    threat_threshold: float = 0.7  # Confidence threshold for blocking
    enable_ml_detection: bool = True
    enable_pattern_matching: bool = True
    enable_anomaly_detection: bool = True

    # SSL/TLS
    enable_ssl: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None

    # Timeouts and limits
    request_timeout: float = 30.0
    connect_timeout: float = 5.0
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    max_header_size: int = 8192  # 8KB

    # IP filtering
    blocked_ips: set = field(default_factory=set)
    allowed_ips: set = field(default_factory=set)

    # Rate limiting
    enable_rate_limiting: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds

    # Advanced features
    enable_websocket: bool = True
    enable_compression: bool = True
    buffer_size: int = 65536  # 64KB
    preserve_host: bool = True
    strip_path_prefix: str = ""

    # Header manipulation
    add_headers: Dict[str, str] = field(default_factory=lambda: {
        "X-Proxy": "CyberShield",
        "X-Forwarded-Proto": "http",
    })
    remove_headers: List[str] = field(default_factory=lambda: [
        "X-Powered-By",
        "Server",
    ])

    # Logging
    log_requests: bool = True
    log_responses: bool = True
    log_body: bool = False  # Be careful with sensitive data

    # Circuit breaker
    enable_circuit_breaker: bool = True
    circuit_breaker_threshold: int = 5  # failures before open
    circuit_breaker_timeout: int = 30  # seconds before half-open

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        """Create configuration from environment variables."""
        config = cls()

        # Server binding
        config.listen_host = os.getenv("PROXY_HOST", "0.0.0.0")
        config.listen_port = int(os.getenv("PROXY_PORT", "8080"))

        # Parse upstream servers from env
        # Format: host1:port1:weight1,host2:port2:weight2
        upstreams_str = os.getenv("PROXY_UPSTREAMS", "")
        if upstreams_str:
            for upstream in upstreams_str.split(","):
                parts = upstream.strip().split(":")
                if len(parts) >= 2:
                    host, port = parts[0], int(parts[1])
                    weight = int(parts[2]) if len(parts) > 2 else 1
                    config.upstream_servers.append(
                        UpstreamServer(host=host, port=port, weight=weight)
                    )

        # Inspection mode
        mode = os.getenv("PROXY_INSPECTION_MODE", "active").lower()
        config.inspection_mode = InspectionMode(mode)

        # Threat threshold
        config.threat_threshold = float(os.getenv("PROXY_THREAT_THRESHOLD", "0.7"))

        # Rate limiting
        config.rate_limit_requests = int(os.getenv("PROXY_RATE_LIMIT", "100"))
        config.rate_limit_window = int(os.getenv("PROXY_RATE_WINDOW", "60"))

        # SSL
        config.enable_ssl = os.getenv("PROXY_SSL_ENABLED", "false").lower() == "true"
        config.ssl_cert_path = os.getenv("PROXY_SSL_CERT")
        config.ssl_key_path = os.getenv("PROXY_SSL_KEY")

        # Blocked IPs
        blocked = os.getenv("PROXY_BLOCKED_IPS", "")
        if blocked:
            config.blocked_ips = set(ip.strip() for ip in blocked.split(","))

        return config

    def add_upstream(
        self,
        host: str,
        port: int,
        weight: int = 1,
        ssl: bool = False,
    ) -> None:
        """Add an upstream server."""
        self.upstream_servers.append(
            UpstreamServer(host=host, port=port, weight=weight, ssl=ssl)
        )

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not self.upstream_servers:
            errors.append("At least one upstream server is required")

        if self.enable_ssl:
            if not self.ssl_cert_path:
                errors.append("SSL enabled but no certificate path provided")
            if not self.ssl_key_path:
                errors.append("SSL enabled but no key path provided")

        if self.threat_threshold < 0 or self.threat_threshold > 1:
            errors.append("Threat threshold must be between 0 and 1")

        return errors
