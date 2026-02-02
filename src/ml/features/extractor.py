"""
Feature Extractor
Extracts features from network traffic for ML models.
"""

from dataclasses import dataclass
from typing import Optional
from collections import defaultdict
from datetime import datetime, timedelta
import numpy as np
import structlog

from src.domain.entities.traffic_event import TrafficEvent

logger = structlog.get_logger(__name__)


@dataclass
class TrafficFeatures:
    """Container for extracted traffic features."""

    # Volume features
    packet_count: int = 0
    byte_count: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # Connection features
    unique_source_ips: int = 0
    unique_destination_ips: int = 0
    unique_source_ports: int = 0
    unique_destination_ports: int = 0
    connection_count: int = 0

    # Protocol distribution
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0

    # Flag features (TCP)
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    syn_ratio: float = 0.0
    syn_ack_ratio: float = 0.0

    # Size features
    avg_packet_size: float = 0.0
    max_packet_size: int = 0
    min_packet_size: int = 0
    packet_size_std: float = 0.0

    # Time features
    avg_inter_arrival_time: float = 0.0
    inter_arrival_time_std: float = 0.0

    # Source analysis
    top_source_ip_ratio: float = 0.0
    source_ip_entropy: float = 0.0

    # Port analysis
    port_scan_score: float = 0.0
    common_port_ratio: float = 0.0

    # Application-layer indicators (for detecting SQL injection, XSS, brute force)
    primary_protocol: str = "tcp"
    primary_target_port: int = 0
    has_sql_indicators: bool = False
    has_xss_indicators: bool = False
    has_brute_force_indicators: bool = False
    payload_patterns: list = None  # Initialized in __post_init__

    def __post_init__(self):
        if self.payload_patterns is None:
            self.payload_patterns = []

    def to_vector(self) -> np.ndarray:
        """Convert features to numpy vector."""
        return np.array([
            self.packet_count,
            self.byte_count,
            self.packets_per_second,
            self.bytes_per_second,
            self.unique_source_ips,
            self.unique_destination_ips,
            self.unique_source_ports,
            self.unique_destination_ports,
            self.connection_count,
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
            self.syn_count,
            self.syn_ack_count,
            self.ack_count,
            self.fin_count,
            self.rst_count,
            self.syn_ratio,
            self.syn_ack_ratio,
            self.avg_packet_size,
            self.max_packet_size,
            self.min_packet_size,
            self.packet_size_std,
            self.avg_inter_arrival_time,
            self.inter_arrival_time_std,
            self.top_source_ip_ratio,
            self.source_ip_entropy,
            self.port_scan_score,
            self.common_port_ratio,
            # Application-layer indicators (as numeric)
            self.primary_target_port,
            1.0 if self.has_sql_indicators else 0.0,
            1.0 if self.has_xss_indicators else 0.0,
            1.0 if self.has_brute_force_indicators else 0.0,
        ], dtype=np.float32)

    @staticmethod
    def feature_names() -> list[str]:
        """Get list of feature names."""
        return [
            "packet_count",
            "byte_count",
            "packets_per_second",
            "bytes_per_second",
            "unique_source_ips",
            "unique_destination_ips",
            "unique_source_ports",
            "unique_destination_ports",
            "connection_count",
            "tcp_ratio",
            "udp_ratio",
            "icmp_ratio",
            "syn_count",
            "syn_ack_count",
            "ack_count",
            "fin_count",
            "rst_count",
            "syn_ratio",
            "syn_ack_ratio",
            "avg_packet_size",
            "max_packet_size",
            "min_packet_size",
            "packet_size_std",
            "avg_inter_arrival_time",
            "inter_arrival_time_std",
            "top_source_ip_ratio",
            "source_ip_entropy",
            "port_scan_score",
            "common_port_ratio",
            "primary_target_port",
            "has_sql_indicators",
            "has_xss_indicators",
            "has_brute_force_indicators",
        ]


class FeatureExtractor:
    """
    Extracts features from network traffic events.

    Aggregates traffic events over time windows and computes
    statistical features for ML model input.
    """

    # Common ports that are typically legitimate targets
    COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080}

    # Authentication service ports (for brute force detection)
    AUTH_PORTS = {22, 21, 23, 3389, 25, 110, 143, 993, 995, 3306, 5432, 1433, 5900}

    # HTTP ports (for SQL injection / XSS detection)
    HTTP_PORTS = {80, 443, 8080, 8443, 3000, 8000, 5000}

    # SQL injection patterns in payloads
    SQL_PATTERNS = [
        "' OR ", "' or ", "1=1", "1'='1", "UNION SELECT", "union select",
        "--", "/*", "*/", "DROP TABLE", "drop table", "INSERT INTO",
        "DELETE FROM", "UPDATE ", "' AND ", "' and ", "EXEC(", "exec(",
        "xp_", "sp_", "@@version", "information_schema", "sys.objects",
    ]

    # XSS patterns in payloads
    XSS_PATTERNS = [
        "<script", "</script>", "javascript:", "onerror=", "onload=",
        "onclick=", "onmouseover=", "onfocus=", "alert(", "eval(",
        "document.cookie", "document.location", "window.location",
        "<img", "<iframe", "<svg", "&#x", "&#", "%3c", "%3e",
    ]

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds

    def extract_from_events(
        self,
        events: list[TrafficEvent],
        time_window: Optional[tuple[datetime, datetime]] = None,
    ) -> TrafficFeatures:
        """
        Extract features from a list of traffic events.

        Args:
            events: List of TrafficEvent objects
            time_window: Optional (start, end) time window

        Returns:
            TrafficFeatures object
        """
        if not events:
            return TrafficFeatures()

        # Filter by time window if specified
        if time_window:
            start, end = time_window
            events = [e for e in events if start <= e.timestamp <= end]

        if not events:
            return TrafficFeatures()

        features = TrafficFeatures()

        # Basic counts
        features.packet_count = len(events)
        features.byte_count = sum(e.packet_size for e in events)

        # Time calculations
        timestamps = sorted(e.timestamp for e in events)
        duration = (timestamps[-1] - timestamps[0]).total_seconds()
        if duration > 0:
            features.packets_per_second = features.packet_count / duration
            features.bytes_per_second = features.byte_count / duration

        # Unique counts
        source_ips = [e.source_ip_str for e in events]
        features.unique_source_ips = len(set(source_ips))
        features.unique_destination_ips = len(set(e.destination_ip_str for e in events))
        features.unique_source_ports = len(set(e.source_port for e in events))
        features.unique_destination_ports = len(set(e.destination_port for e in events))

        # Connection tracking (unique source-destination pairs)
        connections = set(e.flow_tuple for e in events)
        features.connection_count = len(connections)

        # Protocol distribution
        tcp_count = sum(1 for e in events if e.is_tcp)
        udp_count = sum(1 for e in events if e.is_udp)
        icmp_count = sum(1 for e in events if e.is_icmp)

        features.tcp_ratio = tcp_count / features.packet_count if features.packet_count > 0 else 0
        features.udp_ratio = udp_count / features.packet_count if features.packet_count > 0 else 0
        features.icmp_ratio = icmp_count / features.packet_count if features.packet_count > 0 else 0

        # TCP flags
        features.syn_count = sum(1 for e in events if e.has_syn_flag)
        features.syn_ack_count = sum(1 for e in events if e.has_syn_flag and e.has_ack_flag)
        features.ack_count = sum(1 for e in events if e.has_ack_flag)
        features.fin_count = sum(1 for e in events if e.has_fin_flag)
        features.rst_count = sum(1 for e in events if e.has_rst_flag)

        if tcp_count > 0:
            features.syn_ratio = features.syn_count / tcp_count
            features.syn_ack_ratio = features.syn_ack_count / tcp_count

        # Packet size statistics
        packet_sizes = [e.packet_size for e in events]
        features.avg_packet_size = np.mean(packet_sizes)
        features.max_packet_size = max(packet_sizes)
        features.min_packet_size = min(packet_sizes)
        features.packet_size_std = np.std(packet_sizes)

        # Inter-arrival time
        if len(timestamps) > 1:
            inter_arrivals = [
                (timestamps[i] - timestamps[i - 1]).total_seconds()
                for i in range(1, len(timestamps))
            ]
            features.avg_inter_arrival_time = np.mean(inter_arrivals)
            features.inter_arrival_time_std = np.std(inter_arrivals)

        # Source IP analysis
        ip_counts = defaultdict(int)
        for ip in source_ips:
            ip_counts[ip] += 1

        if ip_counts:
            max_count = max(ip_counts.values())
            features.top_source_ip_ratio = max_count / features.packet_count
            features.source_ip_entropy = self._calculate_entropy(list(ip_counts.values()))

        # Port scan detection
        features.port_scan_score = self._calculate_port_scan_score(events)

        # Common port ratio
        dest_ports = [e.destination_port for e in events]
        common_port_count = sum(1 for p in dest_ports if p in self.COMMON_PORTS)
        features.common_port_ratio = common_port_count / len(dest_ports) if dest_ports else 0

        # Application-layer indicators
        features.primary_protocol = self._get_primary_protocol(events)
        features.primary_target_port = self._get_primary_target_port(events)

        # Check for SQL injection patterns
        has_sql, sql_patterns = self._check_sql_patterns(events)
        features.has_sql_indicators = has_sql
        if sql_patterns:
            features.payload_patterns.extend(sql_patterns)

        # Check for XSS patterns
        has_xss, xss_patterns = self._check_xss_patterns(events)
        features.has_xss_indicators = has_xss
        if xss_patterns:
            features.payload_patterns.extend(xss_patterns)

        logger.info(
            "feature_extraction_complete",
            has_sql_indicators=features.has_sql_indicators,
            has_xss_indicators=features.has_xss_indicators,
            payload_patterns_count=len(features.payload_patterns),
            primary_protocol=features.primary_protocol,
        )

        # Check for brute force indicators
        features.has_brute_force_indicators = self._check_brute_force_indicators(
            events, features.top_source_ip_ratio, features.connection_count
        )

        return features

    def extract_windowed(
        self,
        events: list[TrafficEvent],
    ) -> list[TrafficFeatures]:
        """
        Extract features in sliding time windows.

        Args:
            events: List of TrafficEvent objects

        Returns:
            List of TrafficFeatures, one per window
        """
        if not events:
            return []

        # Sort by timestamp
        events = sorted(events, key=lambda e: e.timestamp)

        start_time = events[0].timestamp
        end_time = events[-1].timestamp

        features_list = []
        current_start = start_time

        while current_start <= end_time:
            window_end = current_start + timedelta(seconds=self.window_seconds)
            window_events = [
                e for e in events
                if current_start <= e.timestamp < window_end
            ]

            if window_events:
                features = self.extract_from_events(
                    window_events,
                    time_window=(current_start, window_end),
                )
                features_list.append(features)

            current_start = window_end

        return features_list

    def extract_per_source(
        self,
        events: list[TrafficEvent],
    ) -> dict[str, TrafficFeatures]:
        """
        Extract features grouped by source IP.

        Args:
            events: List of TrafficEvent objects

        Returns:
            Dict mapping source IP to TrafficFeatures
        """
        # Group events by source IP
        ip_events: dict[str, list[TrafficEvent]] = defaultdict(list)
        for event in events:
            ip_events[event.source_ip_str].append(event)

        # Extract features per IP
        return {
            ip: self.extract_from_events(events)
            for ip, events in ip_events.items()
        }

    def _calculate_entropy(self, counts: list[int]) -> float:
        """Calculate Shannon entropy from counts."""
        total = sum(counts)
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)

        return entropy

    def _calculate_port_scan_score(self, events: list[TrafficEvent]) -> float:
        """
        Calculate port scan likelihood score.

        High score indicates potential port scanning activity.
        """
        # Group by source IP
        ip_ports: dict[str, set[int]] = defaultdict(set)
        for event in events:
            ip_ports[event.source_ip_str].add(event.destination_port)

        if not ip_ports:
            return 0.0

        # Calculate max ports per IP
        max_ports_per_ip = max(len(ports) for ports in ip_ports.values())

        # Check for sequential port access
        sequential_score = 0.0
        for ports in ip_ports.values():
            sorted_ports = sorted(ports)
            if len(sorted_ports) > 1:
                sequential_count = sum(
                    1 for i in range(1, len(sorted_ports))
                    if sorted_ports[i] - sorted_ports[i - 1] <= 2
                )
                sequential_score = max(
                    sequential_score,
                    sequential_count / len(sorted_ports),
                )

        # Combine factors
        port_diversity_score = min(1.0, max_ports_per_ip / 100)
        scan_score = (port_diversity_score + sequential_score) / 2

        return scan_score

    def to_matrix(self, features_list: list[TrafficFeatures]) -> np.ndarray:
        """
        Convert list of features to numpy matrix.

        Args:
            features_list: List of TrafficFeatures

        Returns:
            Feature matrix (n_samples, n_features)
        """
        if not features_list:
            return np.array([])

        return np.vstack([f.to_vector() for f in features_list])

    def _check_sql_patterns(self, events: list[TrafficEvent]) -> tuple[bool, list[str]]:
        """
        Check for SQL injection patterns in event metadata/payloads.

        Returns:
            Tuple of (has_indicators, list of matched patterns)
        """
        matched = []
        payloads_checked = 0
        for event in events:
            payload = event.metadata.get("payload", "")
            if payload:
                payloads_checked += 1
                for pattern in self.SQL_PATTERNS:
                    if pattern.lower() in payload.lower():
                        matched.append(pattern)

        if payloads_checked > 0:
            logger.debug(
                "sql_pattern_check",
                payloads_checked=payloads_checked,
                patterns_matched=len(matched),
                matched_patterns=list(set(matched))[:5] if matched else [],
            )
        return len(matched) > 0, list(set(matched))

    def _check_xss_patterns(self, events: list[TrafficEvent]) -> tuple[bool, list[str]]:
        """
        Check for XSS patterns in event metadata/payloads.

        Returns:
            Tuple of (has_indicators, list of matched patterns)
        """
        matched = []
        payloads_checked = 0
        for event in events:
            payload = event.metadata.get("payload", "")
            if payload:
                payloads_checked += 1
                for pattern in self.XSS_PATTERNS:
                    if pattern.lower() in payload.lower():
                        matched.append(pattern)

        if payloads_checked > 0:
            logger.debug(
                "xss_pattern_check",
                payloads_checked=payloads_checked,
                patterns_matched=len(matched),
                matched_patterns=list(set(matched))[:5] if matched else [],
            )
        return len(matched) > 0, list(set(matched))

    def _check_brute_force_indicators(
        self,
        events: list[TrafficEvent],
        top_source_ip_ratio: float,
        connection_count: int,
    ) -> bool:
        """
        Check for brute force attack indicators.

        Brute force characteristics:
        - Single source IP (high top_source_ip_ratio)
        - High connection count
        - Targeting authentication ports
        """
        if top_source_ip_ratio < 0.90 or connection_count < 20:
            return False

        # Check if targeting auth ports
        dest_ports = [e.destination_port for e in events]
        auth_port_count = sum(1 for p in dest_ports if p in self.AUTH_PORTS)
        auth_port_ratio = auth_port_count / len(dest_ports) if dest_ports else 0

        return auth_port_ratio > 0.8

    def _get_primary_protocol(self, events: list[TrafficEvent]) -> str:
        """Get the most common protocol from events."""
        protocol_counts = defaultdict(int)
        for event in events:
            protocol_counts[event.protocol.value] += 1
        if not protocol_counts:
            return "tcp"
        return max(protocol_counts.keys(), key=lambda k: protocol_counts[k])

    def _get_primary_target_port(self, events: list[TrafficEvent]) -> int:
        """Get the most frequently targeted port."""
        port_counts = defaultdict(int)
        for event in events:
            port_counts[event.destination_port] += 1
        if not port_counts:
            return 0
        return max(port_counts.keys(), key=lambda k: port_counts[k])
