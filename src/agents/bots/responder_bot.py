"""
Responder Bot
Response coordination agent that determines appropriate response actions.
Uses Claude AI (Haiku model) for intelligent response planning.

Multi-Model Architecture:
- Uses Haiku for fast, cost-effective action planning
- Orchestrator uses Sonnet for complex decisions
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
import structlog

from src.agents.prompts.responder_prompt import (
    get_responder_system_prompt,
)
from src.agents.llm.claude_client import ClaudeClient, get_agent_client, get_model_for_agent
from src.agents.bots.analyzer_bot import AnalysisResult
from src.domain.entities.threat import Threat
from src.domain.entities.response_action import ResponseAction, ActionType, ActionPriority
from src.infrastructure.health.heartbeat import HeartbeatMixin, HeartbeatManager

logger = structlog.get_logger(__name__)


@dataclass
class ResponsePlan:
    """Response plan from the responder bot."""

    threat_id: UUID
    primary_action: ResponseAction
    secondary_actions: list[ResponseAction]
    monitoring_duration: int
    success_criteria: str
    failure_action: str
    reasoning: str
    false_positive_risk: str
    collateral_impact: str
    reversibility: str
    planning_time_ms: float

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "threat_id": str(self.threat_id),
            "primary_action": self.primary_action.to_dict(),
            "secondary_actions": [a.to_dict() for a in self.secondary_actions],
            "monitoring_duration": self.monitoring_duration,
            "success_criteria": self.success_criteria,
            "failure_action": self.failure_action,
            "reasoning": self.reasoning,
            "false_positive_risk": self.false_positive_risk,
            "collateral_impact": self.collateral_impact,
            "reversibility": self.reversibility,
            "planning_time_ms": self.planning_time_ms,
        }

    def get_all_actions(self) -> list[ResponseAction]:
        """Get all actions in execution order."""
        return [self.primary_action] + self.secondary_actions


class ResponderBot(HeartbeatMixin):
    """
    Response Coordinator Bot.

    Determines and plans appropriate response actions based on
    threat analysis results using Claude AI.
    """

    def __init__(
        self,
        bot_id: str = "responder_001",
        use_llm: bool = True,
        claude_client: Optional[ClaudeClient] = None,
        heartbeat_manager: Optional[HeartbeatManager] = None,
    ):
        self.bot_id = bot_id
        self.bot_type = "responder"
        self.system_prompt = get_responder_system_prompt()
        self._response_count = 0
        self._blocked_ips: set[str] = set()
        self.use_llm = use_llm
        self._claude_client = claude_client

        # Initialize heartbeat tracking
        self._init_heartbeat()
        if heartbeat_manager:
            self.set_heartbeat_manager(heartbeat_manager)

    @property
    def claude_client(self) -> ClaudeClient:
        """Get Claude client (lazy initialization with Haiku model for fast planning)."""
        if self._claude_client is None:
            self._claude_client = get_agent_client("responder")
            logger.info(
                "responder_using_model",
                model=get_model_for_agent("responder"),
                purpose="fast_action_planning",
            )
        return self._claude_client

    async def plan_response(
        self,
        threat: Threat,
        analysis: AnalysisResult,
    ) -> ResponsePlan:
        """
        Plan response actions for a threat.

        Args:
            threat: Detected threat entity
            analysis: Analysis result from analyzer bot

        Returns:
            ResponsePlan with actions to execute
        """
        start_time = datetime.utcnow()
        logger.info(
            "planning_response",
            bot_id=self.bot_id,
            threat_id=str(threat.id),
            attack_type=analysis.attack_type,
        )

        # Record heartbeat - starting planning
        await self.record_heartbeat(processing=True)

        # Check if IP is already blocked
        source_ip = str(threat.source_ip)
        previous_incidents = 1 if source_ip in self._blocked_ips else 0

        # Determine response based on attack type and severity
        plan = self._create_response_plan(
            threat=threat,
            analysis=analysis,
            previous_incidents=previous_incidents,
        )

        # Track blocked IPs
        if plan.primary_action.action_type == ActionType.BLOCK_IP:
            self._blocked_ips.add(source_ip)

        # Calculate planning time
        planning_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        plan.planning_time_ms = planning_time
        self._response_count += 1

        # Record activity completed
        await self.record_activity()

        logger.info(
            "response_planned",
            bot_id=self.bot_id,
            threat_id=str(threat.id),
            primary_action=plan.primary_action.action_type.value,
            secondary_count=len(plan.secondary_actions),
            time_ms=planning_time,
        )

        return plan

    def _create_response_plan(
        self,
        threat: Threat,
        analysis: AnalysisResult,
        previous_incidents: int,
    ) -> ResponsePlan:
        """
        Create a response plan based on threat analysis.

        Uses rule-based logic to determine appropriate response.
        """
        source_ip = str(threat.source_ip)
        severity = analysis.severity
        attack_type = analysis.attack_type

        # Response strategy based on severity
        if severity == "critical":
            return self._critical_response(threat, analysis, source_ip)
        elif severity == "high":
            return self._high_response(threat, analysis, source_ip, previous_incidents)
        elif severity == "medium":
            return self._medium_response(threat, analysis, source_ip)
        else:
            return self._low_response(threat, analysis, source_ip)

    def _critical_response(
        self,
        threat: Threat,
        analysis: AnalysisResult,
        source_ip: str,
    ) -> ResponsePlan:
        """Response plan for critical threats."""
        # Primary: Immediate IP block
        primary = ResponseAction.block_ip(
            threat_id=threat.id,
            ip_address=source_ip,
            duration_seconds=86400,  # 24 hours
            priority=ActionPriority.CRITICAL,
        )
        primary.agent_id = self.bot_id

        # Secondary: Additional actions
        secondary = [
            ResponseAction.create(
                threat_id=threat.id,
                action_type=ActionType.DROP_CONNECTION,
                target=source_ip,
                priority=ActionPriority.CRITICAL,
                agent_id=self.bot_id,
            ),
            ResponseAction.generate_alert(
                threat_id=threat.id,
                alert_message=f"CRITICAL: {analysis.attack_type} attack from {source_ip}",
                severity="critical",
            ),
            ResponseAction.create(
                threat_id=threat.id,
                action_type=ActionType.NOTIFY_UPSTREAM,
                target="upstream_provider",
                priority=ActionPriority.HIGH,
                parameters={"severity": "critical", "source_ip": source_ip},
                agent_id=self.bot_id,
            ),
        ]

        return ResponsePlan(
            threat_id=threat.id,
            primary_action=primary,
            secondary_actions=secondary,
            monitoring_duration=3600,
            success_criteria="Traffic from source drops to zero",
            failure_action="Escalate to NOC team",
            reasoning="Critical threat requires immediate full block and upstream notification",
            false_positive_risk="low",
            collateral_impact="All traffic from source IP blocked",
            reversibility="easy",
            planning_time_ms=0,
        )

    def _high_response(
        self,
        threat: Threat,
        analysis: AnalysisResult,
        source_ip: str,
        previous_incidents: int,
    ) -> ResponsePlan:
        """Response plan for high severity threats."""
        # If repeat offender, block immediately
        if previous_incidents > 0:
            primary = ResponseAction.block_ip(
                threat_id=threat.id,
                ip_address=source_ip,
                duration_seconds=3600,  # 1 hour
                priority=ActionPriority.HIGH,
            )
            reasoning = "Repeat offender - immediate block applied"
        else:
            # First offense - start with rate limiting
            primary = ResponseAction.rate_limit(
                threat_id=threat.id,
                ip_address=source_ip,
                requests_per_second=10,
                duration_seconds=600,
            )
            reasoning = "High threat - rate limiting before escalation to block"

        primary.agent_id = self.bot_id

        secondary = [
            ResponseAction.generate_alert(
                threat_id=threat.id,
                alert_message=f"HIGH: {analysis.attack_type} attack from {source_ip}",
                severity="high",
            ),
        ]

        return ResponsePlan(
            threat_id=threat.id,
            primary_action=primary,
            secondary_actions=secondary,
            monitoring_duration=1800,
            success_criteria="Attack traffic reduced by 80%",
            failure_action="Escalate to IP block",
            reasoning=reasoning,
            false_positive_risk="medium",
            collateral_impact="Rate limited traffic only",
            reversibility="easy",
            planning_time_ms=0,
        )

    def _medium_response(
        self,
        threat: Threat,
        analysis: AnalysisResult,
        source_ip: str,
    ) -> ResponsePlan:
        """Response plan for medium severity threats."""
        primary = ResponseAction.rate_limit(
            threat_id=threat.id,
            ip_address=source_ip,
            requests_per_second=50,
            duration_seconds=300,
        )
        primary.agent_id = self.bot_id

        secondary = [
            ResponseAction.generate_alert(
                threat_id=threat.id,
                alert_message=f"MEDIUM: Suspicious activity from {source_ip}",
                severity="medium",
            ),
        ]

        return ResponsePlan(
            threat_id=threat.id,
            primary_action=primary,
            secondary_actions=secondary,
            monitoring_duration=900,
            success_criteria="Normal traffic patterns resume",
            failure_action="Increase rate limit severity",
            reasoning="Medium threat - moderate rate limiting with monitoring",
            false_positive_risk="medium",
            collateral_impact="Minimal - generous rate limit",
            reversibility="easy",
            planning_time_ms=0,
        )

    def _low_response(
        self,
        threat: Threat,
        analysis: AnalysisResult,
        source_ip: str,
    ) -> ResponsePlan:
        """Response plan for low severity threats."""
        primary = ResponseAction.generate_alert(
            threat_id=threat.id,
            alert_message=f"LOW: Minor anomaly detected from {source_ip}",
            severity="low",
        )
        primary.agent_id = self.bot_id

        return ResponsePlan(
            threat_id=threat.id,
            primary_action=primary,
            secondary_actions=[],
            monitoring_duration=600,
            success_criteria="No escalation in activity",
            failure_action="Re-evaluate threat level",
            reasoning="Low threat - logging and monitoring only",
            false_positive_risk="high",
            collateral_impact="None - monitoring only",
            reversibility="N/A",
            planning_time_ms=0,
        )

    def get_stats(self) -> dict:
        """Get bot statistics."""
        return {
            "bot_id": self.bot_id,
            "bot_type": self.bot_type,
            "response_count": self._response_count,
            "blocked_ips_count": len(self._blocked_ips),
            "health_status": self.get_health_status(),
        }
