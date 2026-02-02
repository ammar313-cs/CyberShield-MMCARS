"""
Traffic Inspector

Analyzes incoming traffic for threats before forwarding.
"""

import asyncio
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from enum import Enum
import structlog

from src.proxy.config import InspectionMode

logger = structlog.get_logger(__name__)


class ThreatType(str, Enum):
    """Types of detected threats."""

    CLEAN = "clean"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    RATE_LIMIT_EXCEEDED = "rate_limit"
    BLOCKED_IP = "blocked_ip"
    MALFORMED_REQUEST = "malformed_request"
    SUSPICIOUS_HEADERS = "suspicious_headers"
    BOT_DETECTED = "bot_detected"
    DDOS_PATTERN = "ddos_pattern"
    CREDENTIAL_STUFFING = "credential_stuffing"


@dataclass
class InspectionResult:
    """Result of traffic inspection."""

    is_threat: bool = False
    threat_type: ThreatType = ThreatType.CLEAN
    confidence: float = 0.0
    details: str = ""
    indicators: List[str] = field(default_factory=list)
    should_block: bool = False
    should_rate_limit: bool = False
    recommended_action: str = "allow"
    inspection_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_threat": self.is_threat,
            "threat_type": self.threat_type.value,
            "confidence": self.confidence,
            "details": self.details,
            "indicators": self.indicators,
            "should_block": self.should_block,
            "should_rate_limit": self.should_rate_limit,
            "recommended_action": self.recommended_action,
            "inspection_time_ms": self.inspection_time_ms,
        }


@dataclass
class RequestContext:
    """Context about an incoming request."""

    client_ip: str
    method: str
    path: str
    query_string: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    content_type: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class TrafficInspector:
    """
    Inspects incoming traffic for threats.

    Performs pattern matching, anomaly detection, and ML-based
    classification to identify malicious traffic.
    """

    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"((\%27)|(\'))select",
        r"exec(\s|\+)+(s|x)p\w+",
        r"union(\s+)select",
        r"insert(\s+)into",
        r"drop(\s+)table",
        r"update(\s+)\w+(\s+)set",
        r"delete(\s+)from",
    ]

    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"expression\s*\(",
        r"document\.(cookie|location|write)",
        r"window\.(location|open)",
        r"eval\s*\(",
        r"alert\s*\(",
    ]

    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`]",
        r"\$\(.*\)",
        r"`.*`",
        r"\|\|",
        r"&&",
        r";.*\b(cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|ruby)\b",
        r"\b(cat|ls|pwd|whoami|id|uname)\s+",
    ]

    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e/",
        r"%2e%2e\\",
        r"\.\.%2f",
        r"\.\.%5c",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
        r"c:/windows",
    ]

    # Suspicious User-Agent patterns
    SUSPICIOUS_USER_AGENTS = [
        r"(nikto|sqlmap|nmap|masscan|dirb|dirbuster|gobuster)",
        r"(havij|sqlninja|w3af|acunetix|nessus|openvas)",
        r"(burp|zaproxy|owasp|arachni|skipfish|wapiti)",
        r"(curl|wget|python-requests|httpie|postman)",  # May be legitimate
    ]

    # Bot patterns
    BOT_PATTERNS = [
        r"bot|crawler|spider|scraper",
        r"headless|phantom|selenium|puppeteer",
    ]

    def __init__(
        self,
        mode: InspectionMode = InspectionMode.ACTIVE,
        threat_threshold: float = 0.7,
        enable_ml: bool = True,
        enable_pattern_matching: bool = True,
    ):
        self.mode = mode
        self.threat_threshold = threat_threshold
        self.enable_ml = enable_ml
        self.enable_pattern_matching = enable_pattern_matching

        # Request tracking for rate limiting and DDoS detection
        self._request_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._blocked_ips: set = set()
        self._rate_limit_window = 60  # seconds
        self._rate_limit_max = 100  # requests per window

        # Compile regex patterns
        self._sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS]
        self._xss_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.XSS_PATTERNS]
        self._cmd_patterns = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        self._path_patterns = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self._ua_patterns = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_USER_AGENTS]
        self._bot_patterns = [re.compile(p, re.IGNORECASE) for p in self.BOT_PATTERNS]

        # Statistics
        self._total_inspected = 0
        self._threats_detected = 0
        self._blocked_requests = 0

        logger.info(
            "traffic_inspector_initialized",
            mode=mode.value,
            threshold=threat_threshold,
        )

    async def inspect(self, context: RequestContext) -> InspectionResult:
        """
        Inspect an incoming request for threats.

        Args:
            context: Request context containing all request details

        Returns:
            InspectionResult with threat assessment
        """
        start_time = datetime.utcnow()
        self._total_inspected += 1

        result = InspectionResult()
        indicators = []
        max_confidence = 0.0
        threat_type = ThreatType.CLEAN

        # 1. Check if IP is blocked
        if context.client_ip in self._blocked_ips:
            result.is_threat = True
            result.threat_type = ThreatType.BLOCKED_IP
            result.confidence = 1.0
            result.should_block = True
            result.details = "IP is in blocked list"
            result.recommended_action = "block"
            return self._finalize_result(result, start_time)

        # 2. Rate limiting check
        rate_result = await self._check_rate_limit(context.client_ip)
        if rate_result.is_threat:
            return self._finalize_result(rate_result, start_time)

        # 3. Pattern matching (if enabled)
        if self.enable_pattern_matching:
            # Combine all inspection targets
            inspection_targets = [
                context.path,
                context.query_string,
            ]

            # Add body if present and text-based
            if context.body and self._is_text_content(context.content_type):
                try:
                    inspection_targets.append(context.body.decode("utf-8", errors="ignore"))
                except Exception:
                    pass

            combined_target = " ".join(filter(None, inspection_targets))

            # SQL Injection
            sql_result = self._check_sql_injection(combined_target)
            if sql_result[0] > max_confidence:
                max_confidence = sql_result[0]
                threat_type = ThreatType.SQL_INJECTION
                indicators.extend(sql_result[1])

            # XSS
            xss_result = self._check_xss(combined_target)
            if xss_result[0] > max_confidence:
                max_confidence = xss_result[0]
                threat_type = ThreatType.XSS
                indicators.extend(xss_result[1])

            # Command Injection
            cmd_result = self._check_command_injection(combined_target)
            if cmd_result[0] > max_confidence:
                max_confidence = cmd_result[0]
                threat_type = ThreatType.COMMAND_INJECTION
                indicators.extend(cmd_result[1])

            # Path Traversal
            path_result = self._check_path_traversal(combined_target)
            if path_result[0] > max_confidence:
                max_confidence = path_result[0]
                threat_type = ThreatType.PATH_TRAVERSAL
                indicators.extend(path_result[1])

            # Suspicious User-Agent
            if context.user_agent:
                ua_result = self._check_user_agent(context.user_agent)
                if ua_result[0] > 0.5:
                    indicators.extend(ua_result[1])
                    # Don't override threat type for UA alone, but note it
                    if max_confidence < ua_result[0]:
                        max_confidence = max(max_confidence, ua_result[0] * 0.7)

        # 4. DDoS pattern detection
        ddos_result = await self._check_ddos_pattern(context.client_ip)
        if ddos_result.is_threat:
            if ddos_result.confidence > max_confidence:
                return self._finalize_result(ddos_result, start_time)
            indicators.append("ddos_pattern_detected")

        # Build final result
        result.is_threat = max_confidence >= self.threat_threshold
        result.threat_type = threat_type if result.is_threat else ThreatType.CLEAN
        result.confidence = max_confidence
        result.indicators = indicators
        result.details = f"Detected patterns: {', '.join(indicators)}" if indicators else "No threats detected"

        # Determine action based on mode and confidence
        if self.mode == InspectionMode.PASSIVE:
            result.should_block = False
            result.recommended_action = "log_only"
        elif self.mode == InspectionMode.STRICT:
            result.should_block = max_confidence >= 0.5
            result.recommended_action = "block" if result.should_block else "allow"
        else:  # ACTIVE mode
            result.should_block = result.is_threat
            result.recommended_action = "block" if result.should_block else "allow"

        if result.is_threat:
            self._threats_detected += 1
            if result.should_block:
                self._blocked_requests += 1

        return self._finalize_result(result, start_time)

    def _finalize_result(
        self, result: InspectionResult, start_time: datetime
    ) -> InspectionResult:
        """Finalize result with timing info."""
        result.inspection_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        return result

    def _is_text_content(self, content_type: Optional[str]) -> bool:
        """Check if content type is text-based."""
        if not content_type:
            return True  # Assume text if not specified
        text_types = [
            "text/",
            "application/json",
            "application/xml",
            "application/x-www-form-urlencoded",
        ]
        return any(t in content_type.lower() for t in text_types)

    def _check_sql_injection(self, target: str) -> Tuple[float, List[str]]:
        """Check for SQL injection patterns."""
        matches = []
        for pattern in self._sql_patterns:
            if pattern.search(target):
                matches.append(f"sql_pattern:{pattern.pattern[:30]}")

        if not matches:
            return 0.0, []

        # More matches = higher confidence
        confidence = min(0.5 + (len(matches) * 0.15), 0.98)
        return confidence, matches

    def _check_xss(self, target: str) -> Tuple[float, List[str]]:
        """Check for XSS patterns."""
        matches = []
        for pattern in self._xss_patterns:
            if pattern.search(target):
                matches.append(f"xss_pattern:{pattern.pattern[:30]}")

        if not matches:
            return 0.0, []

        confidence = min(0.6 + (len(matches) * 0.12), 0.98)
        return confidence, matches

    def _check_command_injection(self, target: str) -> Tuple[float, List[str]]:
        """Check for command injection patterns."""
        matches = []
        for pattern in self._cmd_patterns:
            if pattern.search(target):
                matches.append(f"cmd_pattern:{pattern.pattern[:30]}")

        if not matches:
            return 0.0, []

        confidence = min(0.55 + (len(matches) * 0.15), 0.98)
        return confidence, matches

    def _check_path_traversal(self, target: str) -> Tuple[float, List[str]]:
        """Check for path traversal patterns."""
        matches = []
        for pattern in self._path_patterns:
            if pattern.search(target):
                matches.append(f"path_pattern:{pattern.pattern[:30]}")

        if not matches:
            return 0.0, []

        confidence = min(0.7 + (len(matches) * 0.1), 0.98)
        return confidence, matches

    def _check_user_agent(self, user_agent: str) -> Tuple[float, List[str]]:
        """Check for suspicious user agents."""
        matches = []

        for pattern in self._ua_patterns:
            if pattern.search(user_agent):
                matches.append(f"suspicious_ua:{pattern.pattern[:30]}")

        for pattern in self._bot_patterns:
            if pattern.search(user_agent):
                matches.append(f"bot_ua:{pattern.pattern[:30]}")

        if not matches:
            return 0.0, []

        # User-agent alone shouldn't block, just flag
        confidence = min(0.3 + (len(matches) * 0.15), 0.6)
        return confidence, matches

    async def _check_rate_limit(self, client_ip: str) -> InspectionResult:
        """Check if client has exceeded rate limit."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self._rate_limit_window)

        # Clean old entries
        self._request_counts[client_ip] = [
            ts for ts in self._request_counts[client_ip] if ts > window_start
        ]

        # Add current request
        self._request_counts[client_ip].append(now)

        # Check limit
        request_count = len(self._request_counts[client_ip])
        if request_count > self._rate_limit_max:
            return InspectionResult(
                is_threat=True,
                threat_type=ThreatType.RATE_LIMIT_EXCEEDED,
                confidence=0.95,
                details=f"Rate limit exceeded: {request_count} requests in {self._rate_limit_window}s",
                indicators=[f"rate:{request_count}/{self._rate_limit_max}"],
                should_block=True,
                should_rate_limit=True,
                recommended_action="rate_limit",
            )

        return InspectionResult()

    async def _check_ddos_pattern(self, client_ip: str) -> InspectionResult:
        """Check for DDoS attack patterns."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=5)  # 5 second window for DDoS

        # Count requests in short window
        short_window_count = len([
            ts for ts in self._request_counts[client_ip] if ts > window_start
        ])

        # DDoS threshold: more than 50 requests in 5 seconds
        if short_window_count > 50:
            return InspectionResult(
                is_threat=True,
                threat_type=ThreatType.DDOS_PATTERN,
                confidence=0.9,
                details=f"DDoS pattern detected: {short_window_count} requests in 5s",
                indicators=["ddos_flood", f"burst:{short_window_count}/5s"],
                should_block=True,
                recommended_action="block",
            )

        return InspectionResult()

    def block_ip(self, ip: str) -> None:
        """Add IP to blocked list."""
        self._blocked_ips.add(ip)
        logger.info("ip_blocked", ip=ip)

    def unblock_ip(self, ip: str) -> None:
        """Remove IP from blocked list."""
        self._blocked_ips.discard(ip)
        logger.info("ip_unblocked", ip=ip)

    def set_rate_limit(self, max_requests: int, window_seconds: int) -> None:
        """Update rate limit settings."""
        self._rate_limit_max = max_requests
        self._rate_limit_window = window_seconds
        logger.info(
            "rate_limit_updated",
            max_requests=max_requests,
            window=window_seconds,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get inspector statistics."""
        return {
            "total_inspected": self._total_inspected,
            "threats_detected": self._threats_detected,
            "blocked_requests": self._blocked_requests,
            "blocked_ips_count": len(self._blocked_ips),
            "mode": self.mode.value,
            "threat_threshold": self.threat_threshold,
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._total_inspected = 0
        self._threats_detected = 0
        self._blocked_requests = 0
