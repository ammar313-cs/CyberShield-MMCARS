"""
Agent Orchestrator
Coordinates multi-agent response to security threats with parallel processing.
Uses the AgentRuntime for agentic coordination with shared Claude client.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
import json
import structlog

from src.infrastructure.persistence.redis_client import RedisClient, get_redis_client
from src.infrastructure.health.health_checker import HealthChecker
from src.infrastructure.health.heartbeat import HeartbeatManager
from src.domain.entities.threat import Threat
from src.domain.entities.traffic_event import TrafficEvent
from src.domain.events.threat_detected import (
    ThreatDetectedEvent,
    ThreatConfirmedEvent,
    AttackMitigatedEvent,
    AgentResponseEvent,
)
from src.ml.inference.predictor import ThreatPredictor, ThreatPrediction
from src.ml.features.extractor import TrafficFeatures
from src.agents.llm.claude_client import ClaudeClient, init_claude_client
from src.agents.bots.analyzer_bot import AnalyzerBot, AnalysisResult
from src.agents.bots.responder_bot import ResponderBot, ResponsePlan
from src.agents.bots.mitigator_bot import MitigatorBot, ExecutionResult
from src.agents.bots.reporter_bot import ReporterBot, Alert
from src.agents.bots.monitor_bot import MonitorBot, HealthStatus
from src.agents.runtime.message_bus import MessageBus, AgentMessage, MessageType

logger = structlog.get_logger(__name__)


@dataclass
class OrchestrationResult:
    """Result of threat orchestration."""

    threat_id: UUID
    prediction: ThreatPrediction
    analysis: AnalysisResult
    response_plan: ResponsePlan
    execution_results: list[ExecutionResult]
    alert: Alert
    total_time_ms: float
    success: bool

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "threat_id": str(self.threat_id),
            "prediction": self.prediction.to_dict(),
            "analysis": self.analysis.to_dict(),
            "response_plan": self.response_plan.to_dict(),
            "execution_results": [r.to_dict() for r in self.execution_results],
            "alert": self.alert.to_dict(),
            "total_time_ms": self.total_time_ms,
            "success": self.success,
        }


class AgentOrchestrator:
    """
    Orchestrates multi-agent coordination for threat response.

    Features:
    - Shared Claude client across all LLM-powered agents
    - Parallel threat processing with async message bus
    - Concurrent agent execution for high throughput
    - Redis pub/sub for real-time updates

    Pipeline:
    1. ML Detection -> Prediction (parallel across events)
    2. Analyzer Bot -> Classification (Claude AI)
    3. Responder Bot -> Response Plan (Claude AI)
    4. Mitigator Bot -> Execution (parallel actions)
    5. Reporter Bot -> Alerts (Claude AI)
    6. Monitor Bot -> System Health
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        use_redis: bool = True,
        use_llm: bool = True,
        max_concurrent_threats: int = 10,
    ):
        self.use_redis = use_redis
        self.use_llm = use_llm
        self._redis = redis_client
        self._max_concurrent = max_concurrent_threats

        # Shared Claude client for all agents
        self._claude_client: Optional[ClaudeClient] = None

        # Health checking infrastructure
        self._health_checker: Optional[HealthChecker] = None
        self._heartbeat_manager: Optional[HeartbeatManager] = None

        # Message bus for agent communication
        self._message_bus = MessageBus()

        # Initialize components (will be populated in initialize())
        self.predictor: Optional[ThreatPredictor] = None
        self.analyzer: Optional[AnalyzerBot] = None
        self.responder: Optional[ResponderBot] = None
        self.mitigator: Optional[MitigatorBot] = None
        self.reporter: Optional[ReporterBot] = None
        self.monitor: Optional[MonitorBot] = None

        # State tracking
        self._active_threats: dict[UUID, Threat] = {}
        self._orchestration_count = 0
        self._success_count = 0
        self._is_running = False

        # Concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrent_threats)

        # Pub/Sub channels
        self.THREAT_CHANNEL = "cybershield:threats"
        self.ALERT_CHANNEL = "cybershield:alerts"
        self.EVENT_CHANNEL = "cybershield:events"

        # Redis keys for persistence
        self.METRICS_KEY = "cybershield:metrics"
        self.ACTIVE_THREATS_KEY = "cybershield:active_threats"
        self.ESCALATED_THREATS_KEY = "cybershield:escalated_threats"
        self.AGENT_ACTIONS_KEY = "cybershield:agent_actions"
        self.MAX_AGENT_ACTIONS = 100

        # Escalated threats awaiting human review (in-memory)
        self._escalated_threats: dict[UUID, dict] = {}

    @property
    def claude_client(self) -> Optional[ClaudeClient]:
        """Get the shared Claude client."""
        return self._claude_client

    async def initialize(self) -> None:
        """Initialize the orchestrator with shared Claude client for all agents."""
        logger.info("initializing_agentic_orchestrator")

        # Initialize shared Claude client (single instance for all agents)
        if self.use_llm:
            try:
                self._claude_client = init_claude_client()
                logger.info("shared_claude_client_initialized")
            except Exception as e:
                logger.warning(
                    "claude_client_init_failed",
                    error=str(e),
                    fallback="rule_based",
                )
                self.use_llm = False

        # Initialize ML predictor
        self.predictor = ThreatPredictor()
        await self.predictor.initialize()

        # Initialize health checking infrastructure
        # (Will be fully configured after Redis is connected)
        self._heartbeat_manager = HeartbeatManager()

        # Initialize agents with shared Claude client and heartbeat manager
        self.analyzer = AnalyzerBot(
            bot_id="analyzer_001",
            use_llm=self.use_llm,
            claude_client=self._claude_client,
            heartbeat_manager=self._heartbeat_manager,
        )
        self.responder = ResponderBot(
            bot_id="responder_001",
            use_llm=self.use_llm,
            claude_client=self._claude_client,
            heartbeat_manager=self._heartbeat_manager,
        )
        self.mitigator = MitigatorBot(
            bot_id="mitigator_001",
            heartbeat_manager=self._heartbeat_manager,
        )
        self.reporter = ReporterBot(
            bot_id="reporter_001",
            use_llm=self.use_llm,
            claude_client=self._claude_client,
            heartbeat_manager=self._heartbeat_manager,
        )
        self.monitor = MonitorBot(
            bot_id="monitor_001",
            heartbeat_manager=self._heartbeat_manager,
        )

        # Start message bus
        await self._message_bus.start()

        # Register agents with message bus for parallel communication
        await self._register_agents_with_bus()

        # Initialize Redis if enabled
        if self.use_redis:
            if self._redis is None:
                self._redis = get_redis_client()
            try:
                await self._redis.connect()

                # Now that Redis is connected, set up health checker
                self._health_checker = HealthChecker(redis_client=self._redis)
                self._heartbeat_manager._redis = self._redis

                # Configure monitor bot with health checker
                self.monitor.set_health_checker(self._health_checker)
                self.monitor.set_redis_client(self._redis)

                logger.info("health_checking_infrastructure_initialized")

            except Exception as e:
                logger.warning("redis_connection_failed", error=str(e))
                self.use_redis = False

        self._is_running = True

        # Record initial heartbeats for all agents
        await self._record_initial_heartbeats()
        logger.info(
            "agentic_orchestrator_initialized",
            agents=["analyzer", "responder", "mitigator", "reporter", "monitor"],
            llm_enabled=self.use_llm,
            redis_enabled=self.use_redis,
            max_concurrent=self._max_concurrent,
        )

    async def _record_initial_heartbeats(self) -> None:
        """Record initial heartbeats for all agents."""
        if self._heartbeat_manager:
            try:
                # Record orchestrator heartbeat
                await self._heartbeat_manager.record_heartbeat(
                    agent_id="orchestrator",
                    agent_type="orchestrator",
                )

                # Record heartbeats for all agent bots
                await self.analyzer.record_heartbeat()
                await self.responder.record_heartbeat()
                await self.mitigator.record_heartbeat()
                await self.reporter.record_heartbeat()
                await self.monitor.record_heartbeat()

                logger.info("initial_heartbeats_recorded")
            except Exception as e:
                logger.warning("failed_to_record_initial_heartbeats", error=str(e))

    async def _record_orchestrator_heartbeat(self) -> None:
        """Record periodic heartbeat for orchestrator."""
        if self._heartbeat_manager and self._redis:
            try:
                await self._heartbeat_manager.record_heartbeat(
                    agent_id="orchestrator",
                    agent_type="orchestrator",
                    metadata={
                        "active_threats": len(self._active_threats),
                        "orchestration_count": self._orchestration_count,
                    },
                )

                # Also set a direct Redis key for orchestrator heartbeat
                # (used by health checker)
                await self._redis._client.set(
                    "cybershield:heartbeat:orchestrator",
                    datetime.utcnow().isoformat(),
                    ex=120,  # 2 minute TTL
                )
            except Exception as e:
                logger.warning("failed_to_record_orchestrator_heartbeat", error=str(e))

    async def _register_agents_with_bus(self) -> None:
        """Register all agents with the message bus for parallel processing."""
        # Analyzer listens for new threats
        self._message_bus.register_agent(
            agent_id="analyzer",
            message_types=[MessageType.THREAT_DETECTED],
            handler=self._handle_analyzer_message,
        )
        await self._message_bus.start_processor("analyzer")

        # Responder listens for analysis results
        self._message_bus.register_agent(
            agent_id="responder",
            message_types=[MessageType.THREAT_ANALYZED],
            handler=self._handle_responder_message,
        )
        await self._message_bus.start_processor("responder")

        # Mitigator listens for response plans
        self._message_bus.register_agent(
            agent_id="mitigator",
            message_types=[MessageType.RESPONSE_PLANNED],
            handler=self._handle_mitigator_message,
        )
        await self._message_bus.start_processor("mitigator")

        # Reporter listens for mitigation results
        self._message_bus.register_agent(
            agent_id="reporter",
            message_types=[MessageType.THREAT_MITIGATED, MessageType.SYSTEM_ALERT],
            handler=self._handle_reporter_message,
        )
        await self._message_bus.start_processor("reporter")

    async def _handle_analyzer_message(self, message: AgentMessage) -> None:
        """Handle messages for analyzer agent."""
        # Message handling happens asynchronously in parallel
        logger.debug("analyzer_received_message", message_type=message.type.value)

    async def _handle_responder_message(self, message: AgentMessage) -> None:
        """Handle messages for responder agent."""
        logger.debug("responder_received_message", message_type=message.type.value)

    async def _handle_mitigator_message(self, message: AgentMessage) -> None:
        """Handle messages for mitigator agent."""
        logger.debug("mitigator_received_message", message_type=message.type.value)

    async def _handle_reporter_message(self, message: AgentMessage) -> None:
        """Handle messages for reporter agent."""
        logger.debug("reporter_received_message", message_type=message.type.value)

    async def shutdown(self) -> None:
        """Shutdown the orchestrator."""
        logger.info("shutting_down_orchestrator")
        self._is_running = False

        await self._message_bus.stop()

        # Close health checker resources
        if self._health_checker:
            await self._health_checker.close()

        if self._redis:
            await self._redis.disconnect()

        logger.info("orchestrator_shutdown")

    async def process_traffic(
        self,
        events: list[TrafficEvent],
    ) -> list[OrchestrationResult]:
        """
        Process traffic events through the full detection and response pipeline.

        Threats are processed in parallel using async coordination.

        Args:
            events: List of traffic events to process

        Returns:
            List of OrchestrationResult for detected threats
        """
        if not events:
            return []

        logger.info("processing_traffic", event_count=len(events))

        # Step 1: ML Detection (parallel across all events)
        predictions = await self.predictor.predict(events)

        if not predictions:
            logger.debug("no_threats_detected")
            return []

        # Process threats in parallel with semaphore for rate limiting
        tasks = []
        for prediction in predictions:
            if prediction.threat_level.is_actionable():
                task = self._orchestrate_threat_response(
                    prediction=prediction,
                    events=[e for e in events if e.source_ip_str == prediction.source_ip],
                )
                tasks.append(task)

        # Execute all threat responses concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Filter out exceptions
            return [r for r in results if isinstance(r, OrchestrationResult)]

        return []

    async def process_threats_batch(
        self,
        threats_data: list[tuple[Threat, TrafficFeatures, dict]],
    ) -> list[OrchestrationResult]:
        """
        Process multiple pre-created threats in parallel.

        Args:
            threats_data: List of (threat, features, predictions) tuples

        Returns:
            List of OrchestrationResult
        """
        tasks = []
        for threat, features, predictions in threats_data:
            task = self._process_single_threat(threat, features, predictions)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, OrchestrationResult)]

    async def _process_single_threat(
        self,
        threat: Threat,
        features: TrafficFeatures,
        predictions: dict,
    ) -> OrchestrationResult:
        """Process a single threat through the agentic pipeline."""
        async with self._semaphore:
            return await self._run_agent_pipeline(threat, features, predictions)

    async def _orchestrate_threat_response(
        self,
        prediction: ThreatPrediction,
        events: list[TrafficEvent],
    ) -> OrchestrationResult:
        """
        Orchestrate full threat response through all agents in parallel.

        Args:
            prediction: ML prediction result
            events: Traffic events from threat source

        Returns:
            OrchestrationResult
        """
        async with self._semaphore:
            start_time = datetime.utcnow()
            logger.info(
                "orchestrating_threat_response",
                source_ip=prediction.source_ip,
                threat_score=prediction.threat_level.score,
            )

            # Create threat entity
            threat = Threat.create(
                source_ip=prediction.source_ip,
                attack_signature=prediction.attack_signature,
                threat_level=prediction.threat_level,
                detection_source="ml_engine",
            )

            self._active_threats[threat.id] = threat

            # Broadcast threat detected to message bus
            await self._message_bus.publish(AgentMessage.create(
                type=MessageType.THREAT_DETECTED,
                sender="orchestrator",
                payload={
                    "threat_id": str(threat.id),
                    "source_ip": prediction.source_ip,
                    "threat_score": prediction.threat_level.score,
                },
                priority=1,
            ))

            # Run the agent pipeline
            return await self._run_agent_pipeline(
                threat=threat,
                features=prediction.features,
                predictions=prediction.predictions,
                prediction_result=prediction,
                start_time=start_time,
            )

    async def _run_agent_pipeline(
        self,
        threat: Threat,
        features: TrafficFeatures,
        predictions: dict,
        prediction_result: Optional[ThreatPrediction] = None,
        start_time: Optional[datetime] = None,
    ) -> OrchestrationResult:
        """
        Run the full agent pipeline for a threat.

        Each agent step runs asynchronously, allowing parallel
        processing of multiple threats through the system.
        """
        if start_time is None:
            start_time = datetime.utcnow()

        # Publish threat detected event
        await self._publish_event(ThreatDetectedEvent.create(
            threat_id=threat.id,
            source_ip=str(threat.source_ip),
            attack_type=threat.attack_signature.attack_type.value if threat.attack_signature else "unknown",
            severity=threat.threat_level.severity.value,
            threat_score=threat.threat_level.score,
        ))

        # Step 2: Analysis (async with Claude)
        threat.analyze()
        analysis = await self.analyzer.analyze(
            threat=threat,
            features=features,
            predictions=predictions,
        )

        # Broadcast analysis complete
        await self._message_bus.publish(AgentMessage.create(
            type=MessageType.THREAT_ANALYZED,
            sender="analyzer",
            payload={
                "threat_id": str(threat.id),
                "analysis": analysis.to_dict(),
            },
            priority=2,
        ))

        await self._publish_event(AgentResponseEvent.create(
            agent_id=self.analyzer.bot_id,
            agent_type="analyzer",
            threat_id=threat.id,
            response_type="analysis",
            response_data=analysis.to_dict(),
            processing_time_ms=analysis.analysis_time_ms,
        ))

        # Step 3: Confirm threat
        threat.confirm()
        await self._publish_event(ThreatConfirmedEvent.create(
            threat_id=threat.id,
            confirmed_by=self.analyzer.bot_id,
            updated_severity=analysis.severity,
            confidence=analysis.confidence,
        ))

        # Step 4: Plan response (async with Claude)
        response_plan = await self.responder.plan_response(
            threat=threat,
            analysis=analysis,
        )

        # Broadcast response planned
        await self._message_bus.publish(AgentMessage.create(
            type=MessageType.RESPONSE_PLANNED,
            sender="responder",
            payload={
                "threat_id": str(threat.id),
                "plan": response_plan.to_dict(),
            },
            priority=2,
        ))

        await self._publish_event(AgentResponseEvent.create(
            agent_id=self.responder.bot_id,
            agent_type="responder",
            threat_id=threat.id,
            response_type="response_plan",
            response_data=response_plan.to_dict(),
            processing_time_ms=response_plan.planning_time_ms,
        ))

        # Human-in-the-loop check: Escalate critical/high severity threats
        if analysis.escalation_needed:
            logger.info(
                "escalating_threat_for_human_review",
                threat_id=str(threat.id),
                severity=analysis.severity,
                confidence=analysis.confidence,
            )
            await self._escalate_threat(threat, analysis)

            # Return early - don't auto-mitigate, wait for human decision
            total_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            return OrchestrationResult(
                threat_id=threat.id,
                prediction=prediction_result or ThreatPrediction(
                    source_ip=str(threat.source_ip),
                    is_threat=True,
                    threat_level=threat.threat_level,
                    attack_signature=threat.attack_signature,
                    confidence=analysis.confidence,
                    predictions=predictions,
                    features=features,
                    detection_time=datetime.utcnow(),
                ),
                analysis=analysis,
                response_plan=response_plan,
                execution_results=[],  # No execution - awaiting human
                alert=await self.reporter.generate_alert(
                    threat=threat,
                    analysis=analysis,
                    response_plan=response_plan,
                ),
                total_time_ms=total_time,
                success=False,  # Not mitigated yet - escalated
            )

        # Step 5: Execute mitigation (parallel action execution) - only if not escalated
        threat.start_mitigation(response_plan.primary_action.action_type.value)

        # Execute all actions concurrently
        action_tasks = [
            self.mitigator.execute(action)
            for action in response_plan.get_all_actions()
        ]
        execution_results = await asyncio.gather(*action_tasks)

        # Broadcast mitigation results and persist agent actions
        for result in execution_results:
            await self._publish_event(AgentResponseEvent.create(
                agent_id=self.mitigator.bot_id,
                agent_type="mitigator",
                threat_id=threat.id,
                response_type="execution",
                response_data=result.to_dict(),
                processing_time_ms=result.execution_time_ms,
            ))
            # Persist agent action for dashboard display
            await self._persist_agent_action(
                action_type=result.action_type.value,
                target=result.target,
                agent="Mitigator Bot",
                status=result.status,
                threat_id=str(threat.id),
                threat_type=analysis.attack_type,
                details=f"Response to {analysis.attack_type} attack",
                execution_time_ms=result.execution_time_ms,
            )

        # Check if mitigation was successful
        all_successful = all(r.status == "success" for r in execution_results)
        if all_successful:
            threat.complete_mitigation()

            # Broadcast mitigation complete
            await self._message_bus.publish(AgentMessage.create(
                type=MessageType.THREAT_MITIGATED,
                sender="mitigator",
                payload={
                    "threat_id": str(threat.id),
                    "success": True,
                    "results": [r.to_dict() for r in execution_results],
                },
                priority=3,
            ))

            await self._publish_event(AttackMitigatedEvent.create(
                threat_id=threat.id,
                action_id=response_plan.primary_action.id,
                action_type=response_plan.primary_action.action_type.value,
                target=response_plan.primary_action.target,
                mitigation_duration=(datetime.utcnow() - start_time).total_seconds(),
                success=True,
            ))

            # Cleanup mitigated threat from active tracking (real-time update)
            await self._cleanup_mitigated_threat(threat.id)

        # Step 6: Generate alert (async with Claude for enhanced reports)
        alert = await self.reporter.generate_alert(
            threat=threat,
            analysis=analysis,
            response_plan=response_plan,
            execution_results=list(execution_results),
        )

        # Publish alert
        await self._publish_alert(alert)

        # Calculate total time
        total_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        # Update stats
        self._orchestration_count += 1
        if all_successful:
            self._success_count += 1

        # Persist metrics to Redis
        await self._persist_metrics()

        # Only persist threat if still active (not mitigated/false_positive)
        # Otherwise it was already cleaned up by _cleanup_mitigated_threat
        if threat.is_active:
            await self._persist_threat(threat)

        logger.info(
            "threat_response_complete",
            threat_id=str(threat.id),
            attack_type=analysis.attack_type,
            severity=analysis.severity,
            success=all_successful,
            total_time_ms=total_time,
        )

        # Create a synthetic prediction if not provided
        if prediction_result is None:
            prediction_result = ThreatPrediction(
                source_ip=str(threat.source_ip),
                is_threat=True,
                threat_level=threat.threat_level,
                attack_signature=threat.attack_signature,
                confidence=analysis.confidence,
                predictions=predictions,
                features=features,
                detection_time=datetime.utcnow(),
            )

        return OrchestrationResult(
            threat_id=threat.id,
            prediction=prediction_result,
            analysis=analysis,
            response_plan=response_plan,
            execution_results=list(execution_results),
            alert=alert,
            total_time_ms=total_time,
            success=all_successful,
        )

    async def check_system_health(self) -> HealthStatus:
        """
        Check overall system health.

        Returns:
            HealthStatus assessment
        """
        # Get metrics from tracking
        threats_detected_1h = self._orchestration_count
        threats_mitigated_1h = self._success_count
        active_threats = len(self._active_threats)
        false_positives = 0  # Would be tracked in production

        return await self.monitor.check_health(
            threats_detected_1h=threats_detected_1h,
            threats_mitigated_1h=threats_mitigated_1h,
            active_threats=active_threats,
            false_positives_1h=false_positives,
        )

    async def _publish_event(self, event) -> None:
        """Publish domain event to Redis."""
        if self._redis and self.use_redis:
            try:
                await self._redis.publish(
                    self.EVENT_CHANNEL,
                    json.dumps(event.to_dict()),
                )
            except Exception as e:
                logger.error("failed_to_publish_event", error=str(e))

    async def _publish_alert(self, alert: Alert) -> None:
        """Publish alert to Redis."""
        if self._redis and self.use_redis:
            try:
                await self._redis.publish(
                    self.ALERT_CHANNEL,
                    alert.to_json(),
                )
            except Exception as e:
                logger.error("failed_to_publish_alert", error=str(e))

    async def _persist_metrics(self) -> None:
        """Persist metrics to Redis for dashboard access."""
        if self._redis and self.use_redis:
            try:
                # Count only truly active threats (not mitigated/dismissed)
                active_count = len([t for t in self._active_threats.values() if t.is_active])
                metrics = {
                    "threats_detected_total": self._orchestration_count,
                    "threats_mitigated_total": self._success_count,
                    "active_threats": active_count,
                    "success_rate": (
                        self._success_count / self._orchestration_count
                        if self._orchestration_count > 0
                        else 0.0
                    ),
                    "updated_at": datetime.utcnow().isoformat(),
                }
                await self._redis._client.set(self.METRICS_KEY, json.dumps(metrics))
            except Exception as e:
                logger.error("failed_to_persist_metrics", error=str(e))

    async def _persist_threat(self, threat: Threat) -> None:
        """Persist active threat to Redis."""
        if self._redis and self.use_redis:
            try:
                threat_data = threat.to_dict()
                # Store in hash with threat ID as field
                await self._redis._client.hset(
                    self.ACTIVE_THREATS_KEY,
                    str(threat.id),
                    json.dumps(threat_data),
                )
                # Set expiry on the hash (threats expire after 1 hour)
                await self._redis._client.expire(self.ACTIVE_THREATS_KEY, 3600)

                # Publish threat update for real-time dashboard
                await self._redis.publish(
                    self.THREAT_CHANNEL,
                    json.dumps(threat_data),
                )
            except Exception as e:
                logger.error("failed_to_persist_threat", error=str(e))

    async def _persist_agent_action(
        self,
        action_type: str,
        target: str,
        agent: str,
        status: str,
        threat_id: str,
        threat_type: str,
        details: str = "",
        execution_time_ms: float = 0,
    ) -> None:
        """Persist agent action to Redis for dashboard display."""
        if self._redis and self.use_redis:
            try:
                action_data = {
                    "action_type": action_type,
                    "target": target,
                    "agent": agent,
                    "status": status,
                    "threat_id": threat_id,
                    "threat_type": threat_type,
                    "details": details,
                    "execution_time": f"{execution_time_ms:.1f}ms" if execution_time_ms else "N/A",
                    "effectiveness": "95%" if status == "success" else "N/A",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                # Store in a list (most recent first)
                await self._redis._client.lpush(
                    self.AGENT_ACTIONS_KEY,
                    json.dumps(action_data),
                )
                # Trim to keep only recent actions
                await self._redis._client.ltrim(
                    self.AGENT_ACTIONS_KEY,
                    0,
                    self.MAX_AGENT_ACTIONS - 1,
                )
                # Publish for real-time updates
                await self._redis.publish(
                    self.EVENT_CHANNEL,
                    json.dumps({"type": "agent_action", **action_data}),
                )
            except Exception as e:
                logger.error("failed_to_persist_agent_action", error=str(e))

    async def get_agent_actions(self, count: int = 50) -> list[dict]:
        """Get recent agent actions from Redis."""
        if self._redis and self.use_redis:
            try:
                actions_json = await self._redis._client.lrange(
                    self.AGENT_ACTIONS_KEY, 0, count - 1
                )
                return [json.loads(a) for a in actions_json]
            except Exception as e:
                logger.error("failed_to_get_agent_actions", error=str(e))
        return []

    async def _cleanup_mitigated_threat(self, threat_id: UUID) -> None:
        """
        Remove mitigated threat from active tracking and update metrics.

        Called after successful mitigation to:
        1. Remove from in-memory dict
        2. Remove from Redis hash
        3. Broadcast removal for real-time dashboard update
        4. Update metrics
        """
        # Remove from in-memory dict
        if threat_id in self._active_threats:
            del self._active_threats[threat_id]
            logger.info("threat_removed_from_active", threat_id=str(threat_id))

        # Remove from Redis hash
        if self._redis and self.use_redis:
            try:
                await self._redis._client.hdel(self.ACTIVE_THREATS_KEY, str(threat_id))
            except Exception as e:
                logger.error("failed_to_remove_threat_from_redis", error=str(e))

        # Broadcast removal for real-time dashboard
        await self._publish_threat_removed(threat_id)

        # Update metrics
        await self._persist_metrics()

    async def _publish_threat_removed(self, threat_id: UUID) -> None:
        """Publish threat removed event for real-time dashboard update."""
        if self._redis and self.use_redis:
            try:
                await self._redis.publish(
                    self.THREAT_CHANNEL,
                    json.dumps({
                        "id": str(threat_id),
                        "action": "removed",
                        "timestamp": datetime.utcnow().isoformat(),
                    }),
                )
                logger.debug("threat_removal_broadcasted", threat_id=str(threat_id))
            except Exception as e:
                logger.error("failed_to_broadcast_threat_removal", error=str(e))

    async def _escalate_threat(
        self,
        threat: Threat,
        analysis: AnalysisResult,
    ) -> None:
        """
        Escalate threat for human review.

        Called when the orchestrator (using Sonnet) determines human intervention is needed.
        The threat is moved to an escalation queue and awaits human decision.
        """
        threat.escalate(f"Severity: {analysis.severity}, Confidence: {analysis.confidence}")

        escalation_data = {
            "threat": threat.to_dict(),
            "analysis": analysis.to_dict(),
            "escalated_at": datetime.utcnow().isoformat(),
            "awaiting_action": True,
            "reason": f"{analysis.severity.upper()} severity threat requires human review",
        }

        # Store in memory
        self._escalated_threats[threat.id] = escalation_data

        # Persist to Redis
        if self._redis and self.use_redis:
            try:
                await self._redis._client.hset(
                    self.ESCALATED_THREATS_KEY,
                    str(threat.id),
                    json.dumps(escalation_data),
                )
            except Exception as e:
                logger.error("failed_to_persist_escalation", error=str(e))

        # Broadcast escalation for real-time notification
        await self._publish_escalation_event(threat, analysis)

        logger.info(
            "threat_escalated",
            threat_id=str(threat.id),
            severity=analysis.severity,
            reason="human_review_required",
        )

    async def _publish_escalation_event(
        self,
        threat: Threat,
        analysis: AnalysisResult,
    ) -> None:
        """Publish escalation event for real-time dashboard notification."""
        if self._redis and self.use_redis:
            try:
                await self._redis.publish(
                    self.ALERT_CHANNEL,
                    json.dumps({
                        "type": "escalation",
                        "threat_id": str(threat.id),
                        "source_ip": str(threat.source_ip),
                        "attack_type": analysis.attack_type,
                        "severity": analysis.severity,
                        "confidence": analysis.confidence,
                        "summary": analysis.summary,
                        "requires_human_action": True,
                        "escalated_at": datetime.utcnow().isoformat(),
                    }),
                )
                logger.debug("escalation_event_published", threat_id=str(threat.id))
            except Exception as e:
                logger.error("failed_to_publish_escalation", error=str(e))

    def get_escalated_threats(self) -> list[dict]:
        """Get all threats awaiting human review."""
        return [
            e for e in self._escalated_threats.values()
            if e.get("awaiting_action", False)
        ]

    async def approve_escalation(self, threat_id: UUID) -> bool:
        """
        Human approves mitigation for an escalated threat.

        Runs the full mitigation pipeline for the escalated threat.
        """
        if threat_id not in self._escalated_threats:
            return False

        escalation = self._escalated_threats[threat_id]
        threat = self._active_threats.get(threat_id)

        if not threat:
            logger.warning("escalated_threat_not_found", threat_id=str(threat_id))
            return False

        # Mark as no longer awaiting action
        escalation["awaiting_action"] = False
        escalation["human_decision"] = "approved"
        escalation["decided_at"] = datetime.utcnow().isoformat()

        # Continue with mitigation pipeline
        # (The analysis is cached in escalation data)
        analysis_data = escalation.get("analysis", {})
        analysis = AnalysisResult(
            threat_id=threat.id,
            attack_type=analysis_data.get("attack_type", "unknown"),
            severity=analysis_data.get("severity", "medium"),
            confidence=analysis_data.get("confidence", 0.5),
            summary=analysis_data.get("summary", ""),
            indicators=analysis_data.get("indicators", []),
            attack_vector=analysis_data.get("attack_vector", ""),
            potential_impact=analysis_data.get("potential_impact", ""),
            priority=analysis_data.get("priority", "medium"),
            suggested_actions=analysis_data.get("suggested_actions", []),
            escalation_needed=False,  # Already handled
            analysis_time_ms=analysis_data.get("analysis_time_ms", 0),
        )

        # Run mitigation
        response_plan = await self.responder.plan_response(threat, analysis)
        action_tasks = [
            self.mitigator.execute(action)
            for action in response_plan.get_all_actions()
        ]
        execution_results = await asyncio.gather(*action_tasks)

        all_successful = all(r.status == "success" for r in execution_results)
        if all_successful:
            threat.complete_mitigation()
            await self._cleanup_mitigated_threat(threat.id)

        # Remove from escalation queue
        del self._escalated_threats[threat_id]
        if self._redis and self.use_redis:
            try:
                await self._redis._client.hdel(self.ESCALATED_THREATS_KEY, str(threat_id))
            except Exception:
                pass

        logger.info(
            "escalation_approved",
            threat_id=str(threat_id),
            mitigation_success=all_successful,
        )

        return all_successful

    async def dismiss_escalation(self, threat_id: UUID, reason: str = "Human dismissed") -> bool:
        """
        Human dismisses an escalated threat as false positive.
        """
        if threat_id not in self._escalated_threats:
            return False

        escalation = self._escalated_threats[threat_id]
        threat = self._active_threats.get(threat_id)

        # Mark escalation as handled
        escalation["awaiting_action"] = False
        escalation["human_decision"] = "dismissed"
        escalation["decided_at"] = datetime.utcnow().isoformat()

        if threat:
            threat.mark_false_positive(reason)

        # Remove from active and escalation tracking
        if threat_id in self._active_threats:
            del self._active_threats[threat_id]
        del self._escalated_threats[threat_id]

        # Update Redis
        if self._redis and self.use_redis:
            try:
                await self._redis._client.hdel(self.ACTIVE_THREATS_KEY, str(threat_id))
                await self._redis._client.hdel(self.ESCALATED_THREATS_KEY, str(threat_id))
                await self._publish_threat_removed(threat_id)
                await self._persist_metrics()
            except Exception:
                pass

        logger.info(
            "escalation_dismissed",
            threat_id=str(threat_id),
            reason=reason,
        )

        return True

    async def get_metrics_from_redis(self) -> dict:
        """Get metrics from Redis (for dashboard)."""
        if self._redis and self.use_redis:
            try:
                data = await self._redis._client.get(self.METRICS_KEY)
                if data:
                    return json.loads(data)
            except Exception as e:
                logger.error("failed_to_get_metrics", error=str(e))
        return {}

    async def get_threats_from_redis(self) -> list[dict]:
        """Get active threats from Redis (for dashboard)."""
        if self._redis and self.use_redis:
            try:
                threats = await self._redis._client.hgetall(self.ACTIVE_THREATS_KEY)
                return [json.loads(v) for v in threats.values()]
            except Exception as e:
                logger.error("failed_to_get_threats", error=str(e))
        return []

    def get_active_threats(self) -> list[Threat]:
        """Get list of active threats."""
        return [t for t in self._active_threats.values() if t.is_active]

    def get_agent_stats(self) -> dict:
        """Get statistics from all agents."""
        # Count only truly active threats
        active_count = len([t for t in self._active_threats.values() if t.is_active])
        return {
            "orchestrator": {
                "orchestration_count": self._orchestration_count,
                "success_count": self._success_count,
                "active_threats": active_count,
                "success_rate": (
                    self._success_count / self._orchestration_count
                    if self._orchestration_count > 0
                    else 0.0
                ),
                "llm_enabled": self.use_llm,
                "max_concurrent": self._max_concurrent,
            },
            "analyzer": self.analyzer.get_stats() if self.analyzer else {},
            "responder": self.responder.get_stats() if self.responder else {},
            "mitigator": self.mitigator.get_stats() if self.mitigator else {},
            "reporter": self.reporter.get_stats() if self.reporter else {},
            "monitor": self.monitor.get_stats() if self.monitor else {},
            "message_bus": self._message_bus.get_stats(),
        }


# Entry point for running as service
async def main():
    """Main entry point for agentic service."""
    logger.info("starting_agentic_service")

    orchestrator = AgentOrchestrator(use_llm=True)
    await orchestrator.initialize()

    try:
        # Keep service running
        while orchestrator._is_running:
            # Record orchestrator heartbeat
            await orchestrator._record_orchestrator_heartbeat()

            # Periodic health check
            health = await orchestrator.check_system_health()
            logger.info(
                "system_health",
                overall=health.overall,
                anomalies=len(health.anomalies),
            )
            await asyncio.sleep(30)  # Check every 30 seconds (more frequent for heartbeat)

    except KeyboardInterrupt:
        logger.info("shutdown_requested")
    finally:
        await orchestrator.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
