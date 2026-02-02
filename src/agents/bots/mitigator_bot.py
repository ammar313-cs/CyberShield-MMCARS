"""
Mitigator Bot
Mitigation execution agent that executes response actions.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
import structlog

from src.agents.prompts.mitigator_prompt import (
    get_mitigator_system_prompt,
)
from src.domain.entities.response_action import ResponseAction, ActionType
from src.infrastructure.health.heartbeat import HeartbeatMixin, HeartbeatManager

logger = structlog.get_logger(__name__)


@dataclass
class ExecutionResult:
    """Result of action execution."""

    action_id: UUID
    action_type: ActionType
    target: str
    status: str  # success, partial, failed
    execution_time_ms: float
    verified: bool
    verification_method: str
    threat_reduced: bool
    reduction_percentage: float
    side_effects: list[str]
    continue_monitoring: bool
    adjustment_needed: Optional[str]
    additional_actions: list[str]
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "action_id": str(self.action_id),
            "action_type": self.action_type.value,
            "target": self.target,
            "status": self.status,
            "execution_time_ms": self.execution_time_ms,
            "verified": self.verified,
            "verification_method": self.verification_method,
            "threat_reduced": self.threat_reduced,
            "reduction_percentage": self.reduction_percentage,
            "side_effects": self.side_effects,
            "continue_monitoring": self.continue_monitoring,
            "adjustment_needed": self.adjustment_needed,
            "additional_actions": self.additional_actions,
            "error_message": self.error_message,
        }


class MitigatorBot(HeartbeatMixin):
    """
    Mitigation Executor Bot.

    Executes mitigation actions and verifies their effectiveness.
    """

    def __init__(
        self,
        bot_id: str = "mitigator_001",
        heartbeat_manager: Optional[HeartbeatManager] = None,
    ):
        self.bot_id = bot_id
        self.bot_type = "mitigator"
        self.system_prompt = get_mitigator_system_prompt()
        self._execution_count = 0
        self._success_count = 0
        self._failure_count = 0

        # Initialize heartbeat tracking
        self._init_heartbeat()
        if heartbeat_manager:
            self.set_heartbeat_manager(heartbeat_manager)

        # Simulated state (in production, would interact with actual systems)
        self._blocked_ips: dict[str, datetime] = {}
        self._rate_limits: dict[str, dict] = {}
        self._active_connections: dict[str, int] = {}

    async def execute(self, action: ResponseAction) -> ExecutionResult:
        """
        Execute a mitigation action.

        Args:
            action: ResponseAction to execute

        Returns:
            ExecutionResult with execution status
        """
        start_time = datetime.utcnow()
        logger.info(
            "executing_action",
            bot_id=self.bot_id,
            action_id=str(action.id),
            action_type=action.action_type.value,
            target=action.target,
        )

        # Record heartbeat - starting execution
        await self.record_heartbeat(processing=True)

        # Mark action as executing
        action.start_execution()

        try:
            # Execute based on action type
            if action.action_type == ActionType.BLOCK_IP:
                result = await self._execute_block_ip(action)
            elif action.action_type == ActionType.RATE_LIMIT:
                result = await self._execute_rate_limit(action)
            elif action.action_type == ActionType.DROP_CONNECTION:
                result = await self._execute_drop_connection(action)
            elif action.action_type == ActionType.REDIRECT_HONEYPOT:
                result = await self._execute_redirect_honeypot(action)
            elif action.action_type == ActionType.GENERATE_ALERT:
                result = await self._execute_generate_alert(action)
            elif action.action_type == ActionType.NOTIFY_UPSTREAM:
                result = await self._execute_notify_upstream(action)
            else:
                result = await self._execute_generic(action)

            # Calculate execution time
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            result.execution_time_ms = execution_time

            # Update action status
            if result.status == "success":
                action.complete(result=f"Executed {action.action_type.value} on {action.target}")
                self._success_count += 1
            elif result.status == "partial":
                action.complete(result=f"Partial execution of {action.action_type.value}")
                self._success_count += 1
            else:
                action.fail(error_message=result.error_message or "Execution failed")
                self._failure_count += 1

            self._execution_count += 1

            # Record activity completed
            await self.record_activity()

            logger.info(
                "action_executed",
                bot_id=self.bot_id,
                action_id=str(action.id),
                status=result.status,
                time_ms=execution_time,
            )

            return result

        except Exception as e:
            logger.error(
                "action_execution_failed",
                bot_id=self.bot_id,
                action_id=str(action.id),
                error=str(e),
            )
            action.fail(error_message=str(e))
            self._failure_count += 1
            self._execution_count += 1

            # Record error
            await self.record_error(str(e))

            return ExecutionResult(
                action_id=action.id,
                action_type=action.action_type,
                target=action.target,
                status="failed",
                execution_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
                verified=False,
                verification_method="N/A",
                threat_reduced=False,
                reduction_percentage=0.0,
                side_effects=[],
                continue_monitoring=True,
                adjustment_needed="Retry or escalate",
                additional_actions=["retry", "escalate"],
                error_message=str(e),
            )

    async def _execute_block_ip(self, action: ResponseAction) -> ExecutionResult:
        """Execute IP block action."""
        ip = action.target
        duration = action.parameters.get("duration", 3600)

        # Simulate blocking (in production, would call firewall API)
        await asyncio.sleep(0.01)  # Simulate API call
        self._blocked_ips[ip] = datetime.utcnow()

        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=ip,
            status="success",
            execution_time_ms=0,
            verified=True,
            verification_method="Firewall rule verification",
            threat_reduced=True,
            reduction_percentage=100.0,
            side_effects=[f"All traffic from {ip} blocked"],
            continue_monitoring=True,
            adjustment_needed=None,
            additional_actions=[],
        )

    async def _execute_rate_limit(self, action: ResponseAction) -> ExecutionResult:
        """Execute rate limiting action."""
        ip = action.target
        rate = action.parameters.get("rate_limit", 100)
        duration = action.parameters.get("duration", 300)

        # Simulate rate limiting
        await asyncio.sleep(0.01)
        self._rate_limits[ip] = {"rate": rate, "until": datetime.utcnow()}

        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=ip,
            status="success",
            execution_time_ms=0,
            verified=True,
            verification_method="Rate limit counter check",
            threat_reduced=True,
            reduction_percentage=70.0,
            side_effects=[f"Traffic from {ip} limited to {rate} req/s"],
            continue_monitoring=True,
            adjustment_needed=None,
            additional_actions=[],
        )

    async def _execute_drop_connection(self, action: ResponseAction) -> ExecutionResult:
        """Execute connection drop action."""
        target = action.target

        # Simulate dropping connections
        await asyncio.sleep(0.01)
        connections_dropped = self._active_connections.pop(target, 0)

        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=target,
            status="success",
            execution_time_ms=0,
            verified=True,
            verification_method="Connection table check",
            threat_reduced=True,
            reduction_percentage=100.0,
            side_effects=[f"Dropped {connections_dropped} connections"],
            continue_monitoring=True,
            adjustment_needed=None,
            additional_actions=[],
        )

    async def _execute_redirect_honeypot(self, action: ResponseAction) -> ExecutionResult:
        """Execute honeypot redirect action."""
        target = action.target
        honeypot_id = action.parameters.get("honeypot_id", "default")

        await asyncio.sleep(0.01)

        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=target,
            status="success",
            execution_time_ms=0,
            verified=True,
            verification_method="Honeypot traffic verification",
            threat_reduced=True,
            reduction_percentage=50.0,
            side_effects=[f"Traffic redirected to honeypot {honeypot_id}"],
            continue_monitoring=True,
            adjustment_needed=None,
            additional_actions=["analyze_honeypot_data"],
        )

    async def _execute_generate_alert(self, action: ResponseAction) -> ExecutionResult:
        """Execute alert generation action."""
        message = action.parameters.get("message", "Alert generated")
        severity = action.parameters.get("severity", "medium")

        await asyncio.sleep(0.01)

        logger.warning(
            "security_alert",
            severity=severity,
            message=message,
            threat_id=str(action.threat_id),
        )

        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target="alert_system",
            status="success",
            execution_time_ms=0,
            verified=True,
            verification_method="Alert queue confirmation",
            threat_reduced=False,
            reduction_percentage=0.0,
            side_effects=[f"Alert sent: {severity}"],
            continue_monitoring=True,
            adjustment_needed=None,
            additional_actions=[],
        )

    async def _execute_notify_upstream(self, action: ResponseAction) -> ExecutionResult:
        """Execute upstream notification action."""
        provider = action.target
        severity = action.parameters.get("severity", "high")

        await asyncio.sleep(0.01)

        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=provider,
            status="success",
            execution_time_ms=0,
            verified=True,
            verification_method="Upstream acknowledgment",
            threat_reduced=False,
            reduction_percentage=0.0,
            side_effects=[f"Upstream provider {provider} notified"],
            continue_monitoring=True,
            adjustment_needed=None,
            additional_actions=["await_upstream_response"],
        )

    async def _execute_generic(self, action: ResponseAction) -> ExecutionResult:
        """Execute generic action."""
        await asyncio.sleep(0.01)

        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            status="success",
            execution_time_ms=0,
            verified=True,
            verification_method="Generic verification",
            threat_reduced=False,
            reduction_percentage=0.0,
            side_effects=[],
            continue_monitoring=True,
            adjustment_needed=None,
            additional_actions=[],
        )

    async def rollback(self, action: ResponseAction) -> bool:
        """
        Rollback an executed action.

        Args:
            action: Action to rollback

        Returns:
            True if rollback successful
        """
        logger.info(
            "rolling_back_action",
            bot_id=self.bot_id,
            action_id=str(action.id),
            action_type=action.action_type.value,
        )

        try:
            if action.action_type == ActionType.BLOCK_IP:
                self._blocked_ips.pop(action.target, None)
            elif action.action_type == ActionType.RATE_LIMIT:
                self._rate_limits.pop(action.target, None)

            action.rollback()
            return True
        except Exception as e:
            logger.error("rollback_failed", error=str(e))
            return False

    def get_stats(self) -> dict:
        """Get bot statistics."""
        return {
            "bot_id": self.bot_id,
            "bot_type": self.bot_type,
            "execution_count": self._execution_count,
            "success_count": self._success_count,
            "failure_count": self._failure_count,
            "success_rate": (
                self._success_count / self._execution_count
                if self._execution_count > 0
                else 0.0
            ),
            "active_blocks": len(self._blocked_ips),
            "active_rate_limits": len(self._rate_limits),
            "health_status": self.get_health_status(),
        }
