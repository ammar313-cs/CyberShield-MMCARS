"""
Analyzer Bot
Threat analysis agent that classifies and assesses detected threats.
Uses Claude AI (Haiku model) for intelligent threat analysis.

Multi-Model Architecture:
- Uses Haiku for fast, cost-effective threat classification
- Orchestrator uses Sonnet for complex decisions
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
import structlog

from src.agents.prompts.analyzer_prompt import (
    get_analyzer_system_prompt,
    get_analyzer_user_prompt,
)
from src.agents.llm.claude_client import ClaudeClient, get_agent_client, get_model_for_agent
from src.domain.entities.threat import Threat
from src.ml.features.extractor import TrafficFeatures
from src.ml.models.base_model import PredictionResult
from src.infrastructure.health.heartbeat import HeartbeatMixin, HeartbeatManager

logger = structlog.get_logger(__name__)


@dataclass
class AnalysisResult:
    """Result of threat analysis."""

    threat_id: UUID
    attack_type: str
    severity: str
    confidence: float
    summary: str
    indicators: list[str]
    attack_vector: str
    potential_impact: str
    priority: str
    suggested_actions: list[str]
    escalation_needed: bool
    analysis_time_ms: float
    raw_response: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "threat_id": str(self.threat_id),
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "indicators": self.indicators,
            "attack_vector": self.attack_vector,
            "potential_impact": self.potential_impact,
            "priority": self.priority,
            "suggested_actions": self.suggested_actions,
            "escalation_needed": self.escalation_needed,
            "analysis_time_ms": self.analysis_time_ms,
        }


class AnalyzerBot(HeartbeatMixin):
    """
    Threat Analyzer Bot.

    Analyzes detected threats to classify attack type, assess severity,
    and recommend response priority using Claude AI.
    """

    def __init__(
        self,
        bot_id: str = "analyzer_001",
        use_llm: bool = True,
        claude_client: Optional[ClaudeClient] = None,
        heartbeat_manager: Optional[HeartbeatManager] = None,
    ):
        self.bot_id = bot_id
        self.bot_type = "analyzer"
        self.system_prompt = get_analyzer_system_prompt()
        self._analysis_count = 0
        self.use_llm = use_llm
        self._claude_client = claude_client

        # Initialize heartbeat tracking
        self._init_heartbeat()
        if heartbeat_manager:
            self.set_heartbeat_manager(heartbeat_manager)

    async def analyze(
        self,
        threat: Threat,
        features: TrafficFeatures,
        predictions: dict[str, PredictionResult],
    ) -> AnalysisResult:
        """
        Analyze a detected threat.

        Args:
            threat: Detected threat entity
            features: Extracted traffic features
            predictions: ML model predictions

        Returns:
            AnalysisResult with classification and recommendations
        """
        start_time = datetime.utcnow()
        logger.info(
            "analyzing_threat",
            bot_id=self.bot_id,
            threat_id=str(threat.id),
        )

        # Record heartbeat - starting analysis
        await self.record_heartbeat(processing=True)

        # Build prompt
        detected_patterns = self._extract_patterns(predictions)
        user_prompt = get_analyzer_user_prompt(
            threat_id=str(threat.id),
            source_ip=str(threat.source_ip),
            target_ip=str(threat.target_ip) if threat.target_ip else None,
            target_port=threat.target_port,
            detection_time=threat.detected_at.isoformat(),
            packets_per_second=features.packets_per_second,
            bytes_per_second=features.bytes_per_second,
            unique_source_ips=features.unique_source_ips,
            connection_count=features.connection_count,
            anomaly_score=predictions.get("anomaly", PredictionResult(0, False, 0)).score,
            volume_score=predictions.get("volume", PredictionResult(0, False, 0)).score,
            pattern_score=predictions.get("pattern", PredictionResult(0, False, 0)).score,
            threat_score=threat.threat_level.score,
            syn_ratio=features.syn_ratio,
            port_scan_score=features.port_scan_score,
            top_source_ip_ratio=features.top_source_ip_ratio,
            source_ip_entropy=features.source_ip_entropy,
            detected_patterns=detected_patterns,
        )

        # Perform analysis using Claude AI or fall back to rule-based
        if self.use_llm:
            analysis = await self._llm_analysis(user_prompt, threat, features, predictions)
        else:
            analysis = self._rule_based_analysis(threat, features, predictions)

        # Calculate analysis time
        analysis_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        result = AnalysisResult(
            threat_id=threat.id,
            attack_type=analysis["classification"]["attack_type"],
            severity=analysis["classification"]["severity"],
            confidence=analysis["classification"]["confidence"],
            summary=analysis["analysis"]["summary"],
            indicators=analysis["analysis"]["indicators"],
            attack_vector=analysis["analysis"]["attack_vector"],
            potential_impact=analysis["analysis"]["potential_impact"],
            priority=analysis["recommendations"]["priority"],
            suggested_actions=analysis["recommendations"]["suggested_actions"],
            escalation_needed=analysis["recommendations"]["escalation_needed"],
            analysis_time_ms=analysis_time,
            raw_response=analysis,
        )

        self._analysis_count += 1

        # Record activity completed
        await self.record_activity()

        logger.info(
            "threat_analyzed",
            bot_id=self.bot_id,
            threat_id=str(threat.id),
            attack_type=result.attack_type,
            severity=result.severity,
            time_ms=analysis_time,
        )

        return result

    @property
    def claude_client(self) -> ClaudeClient:
        """Get Claude client (lazy initialization with Haiku model for fast analysis)."""
        if self._claude_client is None:
            self._claude_client = get_agent_client("analyzer")
            logger.info(
                "analyzer_using_model",
                model=get_model_for_agent("analyzer"),
                purpose="fast_threat_classification",
            )
        return self._claude_client

    async def _llm_analysis(
        self,
        user_prompt: str,
        threat: Threat,
        features: TrafficFeatures,
        predictions: dict[str, PredictionResult],
    ) -> dict:
        """
        Perform AI-powered threat analysis using Claude.

        Falls back to rule-based analysis if LLM fails.
        """
        try:
            logger.info(
                "invoking_claude_for_analysis",
                bot_id=self.bot_id,
                threat_id=str(threat.id),
            )

            analysis = await self.claude_client.analyze_threat(
                system_prompt=self.system_prompt,
                user_prompt=user_prompt,
            )

            if analysis:
                logger.info(
                    "claude_analysis_completed",
                    bot_id=self.bot_id,
                    threat_id=str(threat.id),
                    attack_type=analysis.get("classification", {}).get("attack_type"),
                )
                return analysis

            # Fall back to rule-based if parsing failed
            logger.warning(
                "llm_analysis_parse_failed",
                bot_id=self.bot_id,
                threat_id=str(threat.id),
            )
            return self._rule_based_analysis(threat, features, predictions)

        except Exception as e:
            logger.error(
                "llm_analysis_failed",
                bot_id=self.bot_id,
                threat_id=str(threat.id),
                error=str(e),
            )
            # Fall back to rule-based analysis
            return self._rule_based_analysis(threat, features, predictions)

    # Authentication ports for brute force detection
    AUTH_PORTS = {22, 21, 23, 3389, 25, 110, 143, 993, 995, 3306, 5432, 1433, 5900}

    def _rule_based_analysis(
        self,
        threat: Threat,
        features: TrafficFeatures,
        predictions: dict[str, PredictionResult],
    ) -> dict:
        """
        Perform rule-based threat analysis.

        This can be replaced with LLM-based analysis when needed.
        """
        logger.info(
            "analyzer_rule_based_features",
            threat_id=str(threat.id),
            has_sql_indicators=features.has_sql_indicators,
            has_xss_indicators=features.has_xss_indicators,
            has_brute_force_indicators=features.has_brute_force_indicators,
            payload_patterns_count=len(features.payload_patterns) if features.payload_patterns else 0,
        )

        # Determine attack type
        attack_type = "unknown"
        indicators = []

        # Check for SQL injection patterns first (application-layer)
        if features.has_sql_indicators:
            attack_type = "sql_injection"
            indicators.append("SQL injection patterns detected in payload")
            if features.payload_patterns:
                indicators.append(f"Matched patterns: {', '.join(features.payload_patterns[:3])}")

        # Check for XSS attack patterns (application-layer)
        elif features.has_xss_indicators:
            attack_type = "xss_attack"
            indicators.append("XSS script patterns detected in payload")
            if features.payload_patterns:
                indicators.append(f"Matched patterns: {', '.join(features.payload_patterns[:3])}")

        # Check for brute force (application-layer)
        elif features.has_brute_force_indicators:
            attack_type = "brute_force"
            indicators.append("Repeated authentication attempts from single IP")
            indicators.append(f"Target port: {features.primary_target_port}")
        elif (features.top_source_ip_ratio > 0.95 and
              features.connection_count > 30 and
              features.primary_target_port in self.AUTH_PORTS):
            attack_type = "brute_force"
            indicators.append("High connection count to auth service port")
            indicators.append(f"Target port: {features.primary_target_port}")

        # Network-layer attacks
        elif features.syn_ratio > 0.8 and features.syn_ack_ratio < 0.1:
            attack_type = "syn_flood"
            indicators.append("High SYN ratio with low SYN-ACK")

        elif features.port_scan_score > 0.4:  # Lowered threshold
            attack_type = "port_scan"
            indicators.append("Sequential port access pattern")

        elif features.unique_source_ips > 50 and features.packets_per_second > 500:
            attack_type = "ddos"
            indicators.append("Multiple sources with high traffic volume")

        elif features.unique_source_ips > 20 and features.packets_per_second > 200:
            attack_type = "ddos"
            indicators.append("Distributed traffic flood detected")

        elif features.connection_count > 50 and features.avg_packet_size < 100:
            attack_type = "slowloris"
            indicators.append("Many connections with small packets")

        elif predictions.get("anomaly", PredictionResult(0, False, 0)).is_anomaly:
            attack_type = "anomaly"
            indicators.append("ML anomaly detection triggered")

        # Determine severity
        threat_score = threat.threat_level.score
        if threat_score >= 0.9:
            severity = "critical"
        elif threat_score >= 0.7:
            severity = "high"
        elif threat_score >= 0.5:
            severity = "medium"
        else:
            severity = "low"

        # Calculate confidence
        confidence = min(1.0, (len(indicators) * 0.3) + predictions.get(
            "anomaly", PredictionResult(0, False, 0)
        ).confidence * 0.4)

        # Determine priority and actions
        if severity in ("critical", "high"):
            priority = "immediate"
            suggested_actions = ["block_ip", "rate_limit", "generate_alert"]
            escalation_needed = severity == "critical"
        elif severity == "medium":
            priority = "high"
            suggested_actions = ["rate_limit", "generate_alert"]
            escalation_needed = False
        else:
            priority = "medium"
            suggested_actions = ["generate_alert", "monitor"]
            escalation_needed = False

        # Build attack vector description
        attack_vectors = {
            "syn_flood": "TCP SYN flood exploiting three-way handshake",
            "port_scan": "Sequential port probing for service discovery",
            "ddos": "Distributed denial of service through traffic flood",
            "slowloris": "Slow HTTP attack maintaining partial connections",
            "brute_force": "Credential guessing attack targeting authentication service",
            "sql_injection": "SQL injection attack via malicious HTTP payloads",
            "xss_attack": "Cross-site scripting attack via malicious script injection",
            "anomaly": "Unknown anomalous traffic pattern",
            "unknown": "Unclassified suspicious activity",
        }

        # Build impact assessment
        impacts = {
            "critical": "Potential service outage, immediate action required",
            "high": "Service degradation likely, prompt response needed",
            "medium": "Performance impact possible, monitor closely",
            "low": "Minimal impact expected, routine monitoring",
        }

        return {
            "classification": {
                "attack_type": attack_type,
                "confidence": confidence,
                "severity": severity,
            },
            "analysis": {
                "summary": f"Detected {attack_type} attack from {threat.source_ip} with {severity} severity",
                "indicators": indicators,
                "attack_vector": attack_vectors.get(attack_type, "Unknown attack vector"),
                "potential_impact": impacts.get(severity, "Unknown impact"),
            },
            "recommendations": {
                "priority": priority,
                "suggested_actions": suggested_actions,
                "escalation_needed": escalation_needed,
            },
        }

    def _extract_patterns(
        self,
        predictions: dict[str, PredictionResult],
    ) -> list[str]:
        """Extract pattern indicators from predictions."""
        patterns = []
        pattern_result = predictions.get("pattern")
        if pattern_result and pattern_result.details:
            patterns = pattern_result.details.get("indicators", [])
        return patterns

    def get_stats(self) -> dict:
        """Get bot statistics."""
        return {
            "bot_id": self.bot_id,
            "bot_type": self.bot_type,
            "analysis_count": self._analysis_count,
            "health_status": self.get_health_status(),
        }
