"""
Agent Runtime
Manages the agentic system with shared resources and parallel processing.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
import structlog

from src.agents.llm.claude_client import ClaudeClient, init_claude_client
from src.agents.runtime.message_bus import MessageBus, AgentMessage, MessageType
from src.domain.entities.threat import Threat
from src.ml.features.extractor import TrafficFeatures
from src.ml.models.base_model import PredictionResult

logger = structlog.get_logger(__name__)


@dataclass
class ThreatContext:
    """Context for a threat being processed by the agentic system."""

    threat: Threat
    features: Optional[TrafficFeatures] = None
    predictions: Optional[dict[str, PredictionResult]] = None
    analysis_result: Optional[dict] = None
    response_plan: Optional[dict] = None
    mitigation_result: Optional[dict] = None
    report: Optional[str] = None
    status: str = "pending"
    started_at: datetime = None
    completed_at: datetime = None


class AgentRuntime:
    """
    Central runtime for the agentic system.

    Manages:
    - Shared Claude client (single instance for all agents)
    - Message bus for inter-agent communication
    - Parallel threat processing
    - Agent lifecycle management
    """

    _instance: Optional["AgentRuntime"] = None

    def __init__(
        self,
        claude_api_key: Optional[str] = None,
        claude_model: str = "claude-sonnet-4-20250514",
        max_concurrent_threats: int = 10,
    ):
        self._claude_client: Optional[ClaudeClient] = None
        self._claude_api_key = claude_api_key
        self._claude_model = claude_model
        self._message_bus = MessageBus()
        self._agents: dict[str, "BaseAgent"] = {}
        self._threat_contexts: dict[UUID, ThreatContext] = {}
        self._max_concurrent = max_concurrent_threats
        self._semaphore = asyncio.Semaphore(max_concurrent_threats)
        self._running = False
        self._initialized = False

    @classmethod
    def get_instance(cls) -> "AgentRuntime":
        """Get the singleton runtime instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def claude_client(self) -> ClaudeClient:
        """Get the shared Claude client (lazy initialization)."""
        if self._claude_client is None:
            self._claude_client = init_claude_client(
                api_key=self._claude_api_key,
                model=self._claude_model,
            )
            logger.info(
                "shared_claude_client_initialized",
                model=self._claude_model,
            )
        return self._claude_client

    @property
    def message_bus(self) -> MessageBus:
        """Get the message bus."""
        return self._message_bus

    async def initialize(self) -> None:
        """Initialize the runtime and all agents."""
        if self._initialized:
            return

        logger.info("initializing_agent_runtime")

        # Initialize Claude client
        _ = self.claude_client

        # Start message bus
        await self._message_bus.start()

        # Import and initialize agents
        await self._initialize_agents()

        self._initialized = True
        self._running = True
        logger.info("agent_runtime_initialized", agent_count=len(self._agents))

    async def _initialize_agents(self) -> None:
        """Initialize all agents and register with message bus."""
        from src.agents.bots.analyzer_bot import AnalyzerBot
        from src.agents.bots.responder_bot import ResponderBot
        from src.agents.bots.mitigator_bot import MitigatorBot
        from src.agents.bots.reporter_bot import ReporterBot
        from src.agents.bots.monitor_bot import MonitorBot

        # Create agents with shared Claude client
        agents = [
            ("analyzer", AnalyzerBot(
                bot_id="analyzer_001",
                use_llm=True,
                claude_client=self.claude_client,
            )),
            ("responder", ResponderBot(
                bot_id="responder_001",
                use_llm=True,
                claude_client=self.claude_client,
            )),
            ("mitigator", MitigatorBot(bot_id="mitigator_001")),
            ("reporter", ReporterBot(
                bot_id="reporter_001",
                claude_client=self.claude_client,
            )),
            ("monitor", MonitorBot(bot_id="monitor_001")),
        ]

        for name, agent in agents:
            self._agents[name] = agent

            # Register with message bus based on agent type
            message_types = self._get_agent_message_types(name)
            handler = self._create_agent_handler(name, agent)

            self._message_bus.register_agent(
                agent_id=name,
                message_types=message_types,
                handler=handler,
            )

            # Start processor
            await self._message_bus.start_processor(name)

    def _get_agent_message_types(self, agent_name: str) -> list[MessageType]:
        """Get message types an agent should handle."""
        type_mapping = {
            "analyzer": [MessageType.THREAT_DETECTED],
            "responder": [MessageType.THREAT_ANALYZED],
            "mitigator": [MessageType.RESPONSE_PLANNED],
            "reporter": [MessageType.THREAT_MITIGATED, MessageType.SYSTEM_ALERT],
            "monitor": [MessageType.HEALTH_CHECK, MessageType.AGENT_BROADCAST],
        }
        return type_mapping.get(agent_name, [])

    def _create_agent_handler(self, name: str, agent: "BaseAgent") -> callable:
        """Create a message handler for an agent."""

        async def handler(message: AgentMessage) -> None:
            await self._handle_agent_message(name, agent, message)

        return handler

    async def _handle_agent_message(
        self,
        agent_name: str,
        agent: "BaseAgent",
        message: AgentMessage,
    ) -> None:
        """Handle a message for an agent."""
        logger.debug(
            "agent_processing_message",
            agent=agent_name,
            message_type=message.type.value,
            message_id=str(message.id),
        )

        threat_id = message.payload.get("threat_id")
        if threat_id:
            threat_id = UUID(threat_id) if isinstance(threat_id, str) else threat_id

        try:
            if message.type == MessageType.THREAT_DETECTED:
                await self._handle_threat_detected(agent, message, threat_id)

            elif message.type == MessageType.THREAT_ANALYZED:
                await self._handle_threat_analyzed(agent, message, threat_id)

            elif message.type == MessageType.RESPONSE_PLANNED:
                await self._handle_response_planned(agent, message, threat_id)

            elif message.type == MessageType.THREAT_MITIGATED:
                await self._handle_threat_mitigated(agent, message, threat_id)

        except Exception as e:
            logger.error(
                "agent_handler_error",
                agent=agent_name,
                message_type=message.type.value,
                error=str(e),
            )

    async def _handle_threat_detected(
        self,
        agent,
        message: AgentMessage,
        threat_id: UUID,
    ) -> None:
        """Handle threat detected - trigger analysis."""
        context = self._threat_contexts.get(threat_id)
        if not context:
            return

        # Run analysis
        result = await agent.analyze(
            threat=context.threat,
            features=context.features,
            predictions=context.predictions or {},
        )

        context.analysis_result = result.to_dict()
        context.status = "analyzed"

        # Publish analysis complete
        await self._message_bus.publish(AgentMessage.create(
            type=MessageType.THREAT_ANALYZED,
            sender="analyzer",
            payload={
                "threat_id": str(threat_id),
                "analysis": result.to_dict(),
            },
            priority=3,
        ))

    async def _handle_threat_analyzed(
        self,
        agent,
        message: AgentMessage,
        threat_id: UUID,
    ) -> None:
        """Handle analysis complete - trigger response planning."""
        context = self._threat_contexts.get(threat_id)
        if not context:
            return

        from src.agents.bots.analyzer_bot import AnalysisResult

        # Reconstruct analysis result
        analysis_data = message.payload.get("analysis", {})

        # Plan response
        plan = await agent.plan_response(
            threat=context.threat,
            analysis=AnalysisResult(
                threat_id=threat_id,
                attack_type=analysis_data.get("attack_type", "unknown"),
                severity=analysis_data.get("severity", "medium"),
                confidence=analysis_data.get("confidence", 0.5),
                summary=analysis_data.get("summary", ""),
                indicators=analysis_data.get("indicators", []),
                attack_vector=analysis_data.get("attack_vector", ""),
                potential_impact=analysis_data.get("potential_impact", ""),
                priority=analysis_data.get("priority", "medium"),
                suggested_actions=analysis_data.get("suggested_actions", []),
                escalation_needed=analysis_data.get("escalation_needed", False),
                analysis_time_ms=analysis_data.get("analysis_time_ms", 0),
            ),
        )

        context.response_plan = plan.to_dict()
        context.status = "planned"

        # Publish response planned
        await self._message_bus.publish(AgentMessage.create(
            type=MessageType.RESPONSE_PLANNED,
            sender="responder",
            payload={
                "threat_id": str(threat_id),
                "plan": plan.to_dict(),
            },
            priority=2,
        ))

    async def _handle_response_planned(
        self,
        agent,
        message: AgentMessage,
        threat_id: UUID,
    ) -> None:
        """Handle response planned - trigger mitigation."""
        context = self._threat_contexts.get(threat_id)
        if not context:
            return

        plan_data = message.payload.get("plan", {})

        # Execute mitigation
        result = await agent.execute(plan_data)

        context.mitigation_result = result.to_dict()
        context.status = "mitigated"

        # Publish mitigation complete
        await self._message_bus.publish(AgentMessage.create(
            type=MessageType.THREAT_MITIGATED,
            sender="mitigator",
            payload={
                "threat_id": str(threat_id),
                "result": result.to_dict(),
            },
            priority=3,
        ))

    async def _handle_threat_mitigated(
        self,
        agent,
        message: AgentMessage,
        threat_id: UUID,
    ) -> None:
        """Handle mitigation complete - generate report."""
        context = self._threat_contexts.get(threat_id)
        if not context:
            return

        # Generate report
        report = await agent.generate_incident_report(
            threat=context.threat,
            analysis=context.analysis_result,
            response_plan=context.response_plan,
            mitigation_result=context.mitigation_result,
        )

        context.report = report
        context.status = "completed"
        context.completed_at = datetime.utcnow()

        logger.info(
            "threat_processing_complete",
            threat_id=str(threat_id),
            duration_ms=(
                context.completed_at - context.started_at
            ).total_seconds() * 1000,
        )

    async def process_threat(
        self,
        threat: Threat,
        features: TrafficFeatures,
        predictions: dict[str, PredictionResult],
    ) -> ThreatContext:
        """
        Process a threat through the agentic pipeline.

        This is the main entry point - it publishes a threat to the
        message bus and the agents process it asynchronously in parallel.
        """
        async with self._semaphore:
            # Create threat context
            context = ThreatContext(
                threat=threat,
                features=features,
                predictions=predictions,
                started_at=datetime.utcnow(),
            )
            self._threat_contexts[threat.id] = context

            logger.info(
                "processing_threat",
                threat_id=str(threat.id),
                source_ip=str(threat.source_ip),
            )

            # Publish threat detected event
            await self._message_bus.publish(AgentMessage.create(
                type=MessageType.THREAT_DETECTED,
                sender="runtime",
                payload={
                    "threat_id": str(threat.id),
                    "threat": threat.to_dict(),
                },
                priority=1,  # High priority
            ))

            return context

    async def process_threats_batch(
        self,
        threats: list[tuple[Threat, TrafficFeatures, dict[str, PredictionResult]]],
    ) -> list[ThreatContext]:
        """
        Process multiple threats in parallel.

        The agentic system handles them concurrently through the message bus.
        """
        tasks = [
            self.process_threat(threat, features, predictions)
            for threat, features, predictions in threats
        ]
        return await asyncio.gather(*tasks)

    async def wait_for_completion(
        self,
        threat_id: UUID,
        timeout: float = 60.0,
    ) -> Optional[ThreatContext]:
        """Wait for a threat to complete processing."""
        start = datetime.utcnow()

        while (datetime.utcnow() - start).total_seconds() < timeout:
            context = self._threat_contexts.get(threat_id)
            if context and context.status == "completed":
                return context
            await asyncio.sleep(0.1)

        return self._threat_contexts.get(threat_id)

    def get_agent(self, name: str):
        """Get an agent by name."""
        return self._agents.get(name)

    def get_all_agents(self) -> dict:
        """Get all agents."""
        return self._agents.copy()

    def get_threat_context(self, threat_id: UUID) -> Optional[ThreatContext]:
        """Get context for a threat."""
        return self._threat_contexts.get(threat_id)

    async def shutdown(self) -> None:
        """Shutdown the runtime."""
        self._running = False
        await self._message_bus.stop()
        self._agents.clear()
        self._threat_contexts.clear()
        logger.info("agent_runtime_shutdown")

    def get_stats(self) -> dict:
        """Get runtime statistics."""
        return {
            "initialized": self._initialized,
            "running": self._running,
            "agents": list(self._agents.keys()),
            "active_threats": len([
                c for c in self._threat_contexts.values()
                if c.status not in ("completed", "failed")
            ]),
            "total_threats_processed": len(self._threat_contexts),
            "message_bus": self._message_bus.get_stats(),
        }


# Singleton accessor
def get_runtime() -> AgentRuntime:
    """Get the global agent runtime instance."""
    return AgentRuntime.get_instance()
