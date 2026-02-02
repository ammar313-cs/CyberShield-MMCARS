"""
Monitor Bot
System health monitoring agent.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
import psutil
import structlog

from src.agents.prompts.monitor_prompt import get_monitor_system_prompt
from src.infrastructure.health.health_checker import HealthChecker, HealthStatus
from src.infrastructure.health.heartbeat import HeartbeatMixin, HeartbeatManager
from src.infrastructure.persistence.redis_client import RedisClient

logger = structlog.get_logger(__name__)


@dataclass
class HealthStatus:
    """System health status."""

    overall: str  # healthy, degraded, critical
    components: dict[str, str]
    metrics: dict[str, float]
    anomalies: list[dict]
    recommendations: dict[str, list[str]]
    timestamp: datetime

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "overall": self.overall,
            "components": self.components,
            "metrics": self.metrics,
            "anomalies": self.anomalies,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat(),
        }


class MonitorBot(HeartbeatMixin):
    """
    System Monitor Bot.

    Continuously monitors system health and detects anomalies
    in the security infrastructure.
    """

    def __init__(
        self,
        bot_id: str = "monitor_001",
        redis_client: Optional[RedisClient] = None,
        health_checker: Optional[HealthChecker] = None,
        heartbeat_manager: Optional[HeartbeatManager] = None,
    ):
        self.bot_id = bot_id
        self.bot_type = "monitor"
        self.system_prompt = get_monitor_system_prompt()
        self._check_count = 0
        self._anomaly_count = 0

        # Health checking infrastructure
        self._redis = redis_client
        self._health_checker = health_checker
        self._heartbeat_manager = heartbeat_manager

        # Initialize heartbeat tracking
        self._init_heartbeat()

        # Tracking metrics
        self._threats_detected_history: list[tuple[datetime, int]] = []
        self._threats_mitigated_history: list[tuple[datetime, int]] = []
        self._false_positives_history: list[tuple[datetime, int]] = []

        # Component status - now updated via real health checks
        self._component_status: dict[str, str] = {
            "detection_engine": "unknown",
            "response_system": "unknown",
            "agent_coordinator": "unknown",
            "redis_cache": "unknown",
            "api_gateway": "unknown",
        }

        # Baseline metrics
        self._baseline_threats_per_hour = 5.0
        self._baseline_response_time_ms = 100.0

    def set_health_checker(self, health_checker: HealthChecker) -> None:
        """Set the health checker for real service health checks."""
        self._health_checker = health_checker

    def set_redis_client(self, redis_client: RedisClient) -> None:
        """Set the Redis client for health checking."""
        self._redis = redis_client
        if not self._health_checker:
            self._health_checker = HealthChecker(redis_client=redis_client)

    async def check_health(
        self,
        threats_detected_1h: int = 0,
        threats_mitigated_1h: int = 0,
        active_threats: int = 0,
        false_positives_1h: int = 0,
    ) -> HealthStatus:
        """
        Perform system health check.

        Args:
            threats_detected_1h: Threats detected in last hour
            threats_mitigated_1h: Threats mitigated in last hour
            active_threats: Currently active threats
            false_positives_1h: False positives in last hour

        Returns:
            HealthStatus with system assessment
        """
        logger.info(
            "performing_health_check",
            bot_id=self.bot_id,
        )

        # Get system metrics
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        memory_usage = memory.percent

        # Track history
        now = datetime.utcnow()
        self._threats_detected_history.append((now, threats_detected_1h))
        self._threats_mitigated_history.append((now, threats_mitigated_1h))
        self._false_positives_history.append((now, false_positives_1h))

        # Cleanup old history (keep last 24h)
        cutoff = now - timedelta(hours=24)
        self._threats_detected_history = [
            (t, v) for t, v in self._threats_detected_history if t > cutoff
        ]

        # Detect anomalies
        anomalies = await self._detect_anomalies(
            threats_detected_1h=threats_detected_1h,
            threats_mitigated_1h=threats_mitigated_1h,
            active_threats=active_threats,
            false_positives_1h=false_positives_1h,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
        )

        # Update component status based on anomalies
        await self._update_component_status(anomalies)

        # Determine overall status
        overall = self._determine_overall_status(anomalies)

        # Build metrics
        metrics = {
            "threats_detected_1h": threats_detected_1h,
            "threats_mitigated_1h": threats_mitigated_1h,
            "active_threats": active_threats,
            "false_positive_rate": (
                false_positives_1h / threats_detected_1h
                if threats_detected_1h > 0
                else 0.0
            ),
            "mitigation_rate": (
                threats_mitigated_1h / threats_detected_1h
                if threats_detected_1h > 0
                else 1.0
            ),
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
        }

        # Build recommendations
        recommendations = self._generate_recommendations(anomalies, metrics)

        status = HealthStatus(
            overall=overall,
            components=self._component_status.copy(),
            metrics=metrics,
            anomalies=anomalies,
            recommendations=recommendations,
            timestamp=now,
        )

        self._check_count += 1
        self._anomaly_count += len(anomalies)

        logger.info(
            "health_check_complete",
            bot_id=self.bot_id,
            overall=overall,
            anomaly_count=len(anomalies),
        )

        return status

    async def _detect_anomalies(
        self,
        threats_detected_1h: int,
        threats_mitigated_1h: int,
        active_threats: int,
        false_positives_1h: int,
        cpu_usage: float,
        memory_usage: float,
    ) -> list[dict]:
        """Detect system anomalies."""
        anomalies = []

        # High threat volume
        if threats_detected_1h > self._baseline_threats_per_hour * 5:
            anomalies.append({
                "component": "detection_engine",
                "type": "high_threat_volume",
                "severity": "high",
                "description": f"Threat volume {threats_detected_1h}x higher than baseline",
            })

        # Low mitigation rate
        if threats_detected_1h > 0:
            mitigation_rate = threats_mitigated_1h / threats_detected_1h
            if mitigation_rate < 0.8:
                anomalies.append({
                    "component": "response_system",
                    "type": "low_mitigation_rate",
                    "severity": "medium",
                    "description": f"Mitigation rate at {mitigation_rate:.0%}, below 80% target",
                })

        # High false positive rate
        if threats_detected_1h > 0:
            fp_rate = false_positives_1h / threats_detected_1h
            if fp_rate > 0.2:
                anomalies.append({
                    "component": "detection_engine",
                    "type": "high_false_positive_rate",
                    "severity": "medium",
                    "description": f"False positive rate at {fp_rate:.0%}, above 20% threshold",
                })

        # Too many active threats
        if active_threats > 10:
            anomalies.append({
                "component": "response_system",
                "type": "threat_backlog",
                "severity": "high",
                "description": f"{active_threats} active threats awaiting mitigation",
            })

        # Resource constraints
        if cpu_usage > 80:
            anomalies.append({
                "component": "api_gateway",
                "type": "high_cpu",
                "severity": "medium",
                "description": f"CPU usage at {cpu_usage:.0f}%",
            })

        if memory_usage > 85:
            anomalies.append({
                "component": "api_gateway",
                "type": "high_memory",
                "severity": "high",
                "description": f"Memory usage at {memory_usage:.0f}%",
            })

        return anomalies

    async def _update_component_status(self, anomalies: list[dict]) -> None:
        """
        Update component status using real health checks combined with anomaly detection.

        First performs actual service health checks, then overlays anomaly-based status
        where anomalies indicate worse conditions than the health check found.
        """
        # Record heartbeat for this bot
        await self.record_heartbeat(processing=True)

        # Step 1: Perform real health checks if available
        if self._health_checker:
            try:
                health_results = await self._health_checker.check_all_components()

                # Convert health check results to status strings
                for name, health in health_results.items():
                    self._component_status[name] = self._health_checker.get_status_string(health)

                logger.debug(
                    "real_health_check_completed",
                    bot_id=self.bot_id,
                    components=self._component_status,
                )
            except Exception as e:
                logger.error("health_check_failed", error=str(e))
                # Fall back to marking Redis-dependent components as unknown
                self._component_status["redis_cache"] = "critical"
        else:
            # No health checker - reset all to healthy as baseline
            for component in self._component_status:
                self._component_status[component] = "healthy"

        # Step 2: Overlay anomaly-based status (only if worse than health check)
        for anomaly in anomalies:
            component = anomaly["component"]
            severity = anomaly["severity"]

            if component in self._component_status:
                current = self._component_status[component]

                # Only upgrade severity (healthy -> degraded -> critical)
                if severity == "high" and current != "critical":
                    self._component_status[component] = "critical"
                elif severity == "medium" and current == "healthy":
                    self._component_status[component] = "degraded"

        # Record activity completed
        await self.record_activity()

    def _determine_overall_status(self, anomalies: list[dict]) -> str:
        """Determine overall system status."""
        high_severity = sum(1 for a in anomalies if a["severity"] == "high")
        medium_severity = sum(1 for a in anomalies if a["severity"] == "medium")

        if high_severity >= 2:
            return "critical"
        elif high_severity >= 1 or medium_severity >= 3:
            return "degraded"
        else:
            return "healthy"

    def _generate_recommendations(
        self,
        anomalies: list[dict],
        metrics: dict,
    ) -> dict[str, list[str]]:
        """Generate recommendations based on anomalies."""
        immediate = []
        maintenance = []

        for anomaly in anomalies:
            if anomaly["severity"] == "high":
                if anomaly["type"] == "high_threat_volume":
                    immediate.append("Enable additional detection capacity")
                    immediate.append("Consider activating backup mitigation systems")
                elif anomaly["type"] == "threat_backlog":
                    immediate.append("Increase response agent parallelism")
                    immediate.append("Consider automatic escalation rules")
                elif anomaly["type"] == "high_memory":
                    immediate.append("Clear caches and temporary data")
                    immediate.append("Consider horizontal scaling")

            elif anomaly["severity"] == "medium":
                if anomaly["type"] == "low_mitigation_rate":
                    maintenance.append("Review mitigation strategies effectiveness")
                    maintenance.append("Update response playbooks")
                elif anomaly["type"] == "high_false_positive_rate":
                    maintenance.append("Retrain detection models")
                    maintenance.append("Review detection thresholds")
                elif anomaly["type"] == "high_cpu":
                    maintenance.append("Optimize heavy computations")
                    maintenance.append("Schedule resource-intensive tasks during low traffic")

        # Add general maintenance tasks
        if not maintenance:
            maintenance.append("Run routine health diagnostics")
            maintenance.append("Review and rotate logs")

        return {
            "immediate": immediate,
            "maintenance": maintenance,
        }

    def update_component_status(self, component: str, status: str) -> None:
        """Manually update component status."""
        if component in self._component_status:
            self._component_status[component] = status
            logger.info(
                "component_status_updated",
                bot_id=self.bot_id,
                component=component,
                status=status,
            )

    async def check_service_health(self) -> dict[str, str]:
        """
        Perform actual service health checks.

        Returns:
            Dict mapping component name to status string
        """
        if not self._health_checker:
            return self._component_status.copy()

        try:
            health_results = await self._health_checker.check_all_components()
            return {
                name: self._health_checker.get_status_string(health)
                for name, health in health_results.items()
            }
        except Exception as e:
            logger.error("service_health_check_failed", error=str(e))
            return self._component_status.copy()

    def get_stats(self) -> dict:
        """Get bot statistics."""
        return {
            "bot_id": self.bot_id,
            "bot_type": self.bot_type,
            "check_count": self._check_count,
            "anomaly_count": self._anomaly_count,
            "component_status": self._component_status,
            "health_status": self.get_health_status(),
        }
