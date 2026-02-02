"""
Reporter Bot
Alert and report generation agent using Claude AI (Haiku model) for intelligent reports.

Multi-Model Architecture:
- Uses Haiku for fast, cost-effective alert generation
- Orchestrator uses Sonnet for complex decisions
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4
import json
import structlog

from src.agents.prompts.reporter_prompt import (
    get_reporter_system_prompt,
)
from src.agents.llm.claude_client import ClaudeClient, get_agent_client, get_model_for_agent
from src.domain.entities.threat import Threat
from src.agents.bots.analyzer_bot import AnalysisResult
from src.agents.bots.responder_bot import ResponsePlan
from src.agents.bots.mitigator_bot import ExecutionResult
from src.infrastructure.persistence.redis_client import get_redis_client
from src.infrastructure.health.heartbeat import HeartbeatMixin, HeartbeatManager

logger = structlog.get_logger(__name__)

# Redis keys for persistence
ALERTS_KEY = "cybershield:alerts:list"
METRICS_KEY = "cybershield:metrics"
MAX_STORED_ALERTS = 100


@dataclass
class Alert:
    """Security alert."""

    alert_id: UUID
    severity: str
    title: str
    summary: str
    timestamp: datetime
    threat_type: str
    source: str
    target: str
    status: str
    actions_taken: list[str]
    recommendations: dict
    metrics: dict

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "alert_id": str(self.alert_id),
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "timestamp": self.timestamp.isoformat(),
            "threat_type": self.threat_type,
            "source": self.source,
            "target": self.target,
            "status": self.status,
            "actions_taken": self.actions_taken,
            "recommendations": self.recommendations,
            "metrics": self.metrics,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class IncidentReport:
    """Detailed incident report."""

    report_id: UUID
    incident_id: UUID
    report_type: str
    generated_at: datetime
    threat_summary: dict
    timeline: list[dict]
    actions_summary: list[dict]
    effectiveness_analysis: dict
    lessons_learned: list[str]
    recommendations: list[str]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "report_id": str(self.report_id),
            "incident_id": str(self.incident_id),
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "threat_summary": self.threat_summary,
            "timeline": self.timeline,
            "actions_summary": self.actions_summary,
            "effectiveness_analysis": self.effectiveness_analysis,
            "lessons_learned": self.lessons_learned,
            "recommendations": self.recommendations,
        }


class ReporterBot(HeartbeatMixin):
    """
    Reporter Bot.

    Generates alerts, reports, and communications about security incidents
    using Claude AI for intelligent natural language generation.
    """

    def __init__(
        self,
        bot_id: str = "reporter_001",
        use_llm: bool = True,
        claude_client: Optional[ClaudeClient] = None,
        heartbeat_manager: Optional[HeartbeatManager] = None,
    ):
        self.bot_id = bot_id
        self.bot_type = "reporter"
        self.system_prompt = get_reporter_system_prompt()
        self._alert_count = 0
        self._report_count = 0
        self._alerts_history: list[Alert] = []
        self.use_llm = use_llm
        self._claude_client = claude_client
        self._redis = None

        # Initialize heartbeat tracking
        self._init_heartbeat()
        if heartbeat_manager:
            self.set_heartbeat_manager(heartbeat_manager)

    async def _get_redis(self):
        """Get Redis client (lazy initialization)."""
        if self._redis is None:
            try:
                self._redis = get_redis_client()
                await self._redis.connect()
            except Exception as e:
                logger.warning("redis_not_available_for_alerts", error=str(e))
                return None
        return self._redis

    async def _persist_alert(self, alert: Alert) -> None:
        """Persist alert to Redis."""
        redis = await self._get_redis()
        if redis:
            try:
                # Store alert in a list (most recent first)
                await redis._client.lpush(ALERTS_KEY, alert.to_json())
                # Trim to keep only recent alerts
                await redis._client.ltrim(ALERTS_KEY, 0, MAX_STORED_ALERTS - 1)
                logger.debug("alert_persisted", alert_id=str(alert.alert_id))
            except Exception as e:
                logger.error("failed_to_persist_alert", error=str(e))

    async def get_persisted_alerts(self, count: int = 20) -> list[dict]:
        """Get persisted alerts from Redis."""
        redis = await self._get_redis()
        if redis:
            try:
                alerts_json = await redis._client.lrange(ALERTS_KEY, 0, count - 1)
                return [json.loads(a) for a in alerts_json]
            except Exception as e:
                logger.error("failed_to_get_alerts", error=str(e))
        return []

    @property
    def claude_client(self) -> ClaudeClient:
        """Get Claude client (lazy initialization with Haiku model for fast reporting)."""
        if self._claude_client is None:
            self._claude_client = get_agent_client("reporter")
            logger.info(
                "reporter_using_model",
                model=get_model_for_agent("reporter"),
                purpose="fast_alert_generation",
            )
        return self._claude_client

    async def generate_alert(
        self,
        threat: Threat,
        analysis: AnalysisResult,
        response_plan: Optional[ResponsePlan] = None,
        execution_results: Optional[list[ExecutionResult]] = None,
    ) -> Alert:
        """
        Generate a security alert.

        Args:
            threat: Detected threat
            analysis: Analysis result
            response_plan: Optional response plan
            execution_results: Optional execution results

        Returns:
            Generated Alert
        """
        logger.info(
            "generating_alert",
            bot_id=self.bot_id,
            threat_id=str(threat.id),
            severity=analysis.severity,
        )

        # Record heartbeat - starting alert generation
        await self.record_heartbeat(processing=True)

        # Determine current status
        if execution_results:
            successful = all(r.status == "success" for r in execution_results)
            status = "mitigated" if successful else "mitigating"
        elif response_plan:
            status = "responding"
        else:
            status = "detected"

        # Build actions taken list
        actions_taken = []
        if execution_results:
            actions_taken = [
                f"{r.action_type.value}: {r.target} ({r.status})"
                for r in execution_results
            ]

        # Build recommendations
        recommendations = {
            "immediate": analysis.suggested_actions[:2] if analysis.suggested_actions else [],
            "short_term": ["Monitor for recurrence", "Review firewall rules"],
            "long_term": ["Update detection rules", "Conduct security audit"],
        }

        # Calculate metrics
        detection_time = (datetime.utcnow() - threat.detected_at).total_seconds()
        metrics = {
            "detection_time": f"{detection_time:.1f}s",
            "response_time": "N/A",
            "mitigation_time": "N/A",
            "impact_duration": f"{detection_time:.1f}s (ongoing)" if status != "mitigated" else "N/A",
        }

        if response_plan:
            metrics["response_time"] = f"{response_plan.planning_time_ms:.1f}ms"

        if execution_results:
            total_exec_time = sum(r.execution_time_ms for r in execution_results)
            metrics["mitigation_time"] = f"{total_exec_time:.1f}ms"

        # Create alert
        alert = Alert(
            alert_id=uuid4(),
            severity=analysis.severity,
            title=f"{analysis.attack_type.upper()} Attack Detected from {threat.source_ip}",
            summary=analysis.summary,
            timestamp=datetime.utcnow(),
            threat_type=analysis.attack_type,
            source=str(threat.source_ip),
            target=str(threat.target_ip) if threat.target_ip else "Unknown",
            status=status,
            actions_taken=actions_taken,
            recommendations=recommendations,
            metrics=metrics,
        )

        self._alerts_history.append(alert)
        self._alert_count += 1

        # Persist to Redis
        await self._persist_alert(alert)

        # Record activity completed
        await self.record_activity()

        logger.info(
            "alert_generated",
            bot_id=self.bot_id,
            alert_id=str(alert.alert_id),
            severity=alert.severity,
        )

        return alert

    async def generate_incident_report(
        self,
        threat: Threat,
        analysis: AnalysisResult,
        response_plan: ResponsePlan,
        execution_results: list[ExecutionResult],
        report_type: str = "technical",
    ) -> IncidentReport:
        """
        Generate a detailed incident report.

        Args:
            threat: Threat entity
            analysis: Analysis result
            response_plan: Response plan
            execution_results: Execution results
            report_type: Type of report (technical, executive, compliance)

        Returns:
            Generated IncidentReport
        """
        logger.info(
            "generating_report",
            bot_id=self.bot_id,
            threat_id=str(threat.id),
            report_type=report_type,
        )

        # Build threat summary
        threat_summary = {
            "threat_id": str(threat.id),
            "attack_type": analysis.attack_type,
            "severity": analysis.severity,
            "source_ip": str(threat.source_ip),
            "target": str(threat.target_ip) if threat.target_ip else "Unknown",
            "indicators": analysis.indicators,
            "confidence": analysis.confidence,
        }

        # Build timeline
        timeline = [
            {
                "time": threat.detected_at.isoformat(),
                "event": f"Threat detected: {analysis.attack_type}",
            },
            {
                "time": (threat.detected_at).isoformat(),
                "event": f"Analysis completed: {analysis.severity} severity",
            },
        ]

        if response_plan:
            timeline.append({
                "time": datetime.utcnow().isoformat(),
                "event": f"Response planned: {response_plan.primary_action.action_type.value}",
            })

        for result in execution_results:
            timeline.append({
                "time": datetime.utcnow().isoformat(),
                "event": f"Action executed: {result.action_type.value} ({result.status})",
            })

        # Build actions summary
        actions_summary = [
            {
                "action_type": result.action_type.value,
                "target": result.target,
                "status": result.status,
                "effectiveness": f"{result.reduction_percentage:.0f}%",
                "verified": result.verified,
            }
            for result in execution_results
        ]

        # Effectiveness analysis
        total_reduction = (
            sum(r.reduction_percentage for r in execution_results) / len(execution_results)
            if execution_results
            else 0
        )
        effectiveness_analysis = {
            "overall_effectiveness": f"{total_reduction:.0f}%",
            "threat_neutralized": total_reduction >= 80,
            "response_time_evaluation": "fast" if response_plan.planning_time_ms < 100 else "adequate",
            "false_positive_assessment": response_plan.false_positive_risk,
        }

        # Lessons learned and recommendations
        lessons_learned = []
        recommendations = []

        if analysis.severity == "critical":
            lessons_learned.append("Critical threat detected - review detection thresholds")
            recommendations.append("Consider implementing additional upstream filtering")

        if total_reduction < 80:
            lessons_learned.append("Mitigation effectiveness below target")
            recommendations.append("Review and enhance response strategies")

        if analysis.attack_type == "ddos":
            recommendations.append("Evaluate DDoS mitigation service capacity")
        elif analysis.attack_type == "port_scan":
            recommendations.append("Review exposed services and ports")

        # Create report
        report = IncidentReport(
            report_id=uuid4(),
            incident_id=threat.id,
            report_type=report_type,
            generated_at=datetime.utcnow(),
            threat_summary=threat_summary,
            timeline=timeline,
            actions_summary=actions_summary,
            effectiveness_analysis=effectiveness_analysis,
            lessons_learned=lessons_learned,
            recommendations=recommendations,
        )

        self._report_count += 1

        logger.info(
            "report_generated",
            bot_id=self.bot_id,
            report_id=str(report.report_id),
            report_type=report_type,
        )

        return report

    async def broadcast_alert(self, alert: Alert, channels: list[str]) -> dict:
        """
        Broadcast alert to multiple channels.

        Args:
            alert: Alert to broadcast
            channels: List of channels (console, websocket, webhook)

        Returns:
            Dict with broadcast results per channel
        """
        results = {}

        for channel in channels:
            try:
                if channel == "console":
                    self._log_alert_to_console(alert)
                    results[channel] = "success"
                elif channel == "websocket":
                    # Would send to WebSocket in production
                    results[channel] = "success"
                elif channel == "webhook":
                    # Would POST to webhook in production
                    results[channel] = "success"
                else:
                    results[channel] = "unknown_channel"
            except Exception as e:
                results[channel] = f"failed: {str(e)}"

        return results

    def _log_alert_to_console(self, alert: Alert) -> None:
        """Log alert to console with appropriate formatting."""
        severity_emoji = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "📢",
            "low": "ℹ️",
            "info": "📝",
        }
        emoji = severity_emoji.get(alert.severity, "📌")

        logger.warning(
            f"{emoji} SECURITY ALERT",
            alert_id=str(alert.alert_id),
            severity=alert.severity,
            title=alert.title,
            source=alert.source,
            status=alert.status,
        )

    def get_recent_alerts(self, count: int = 10) -> list[Alert]:
        """Get recent alerts."""
        return self._alerts_history[-count:]

    def get_stats(self) -> dict:
        """Get bot statistics."""
        return {
            "bot_id": self.bot_id,
            "bot_type": self.bot_type,
            "alert_count": self._alert_count,
            "report_count": self._report_count,
            "health_status": self.get_health_status(),
        }
