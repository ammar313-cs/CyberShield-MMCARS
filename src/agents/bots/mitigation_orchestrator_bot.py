"""
Mitigation Orchestrator Bot
Dynamic multi-agent coordinator for complex threat mitigation workflows.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable, Any
from uuid import UUID, uuid4
import structlog

from src.domain.entities.threat import Threat
from src.domain.entities.response_action import ResponseAction, ActionType

logger = structlog.get_logger(__name__)


class AgentState(Enum):
    """State of a spawned agent."""
    PENDING = "pending"
    SPAWNING = "spawning"
    ACTIVE = "active"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class MitigationPolicy(Enum):
    """Security policies for different severity levels."""
    DEFCON_1 = "defcon_1"  # Critical - Emergency Response
    ACTIVE_DEFENSE = "active_defense"  # High - Active Defense Protocol
    STANDARD = "standard"  # Medium - Standard Response
    MONITORING = "monitoring"  # Low - Monitoring Only


@dataclass
class SpawnedAgent:
    """Represents a dynamically spawned agent."""
    id: str
    name: str
    agent_type: str
    state: AgentState
    spawn_time: datetime
    actions: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    execution_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "agent_type": self.agent_type,
            "state": self.state.value,
            "spawn_time": self.spawn_time.isoformat(),
            "actions": self.actions,
            "results": self.results,
            "execution_time_ms": self.execution_time_ms,
        }


@dataclass
class MitigationWorkflow:
    """Represents a mitigation workflow with multiple agents."""
    id: UUID
    threat_id: UUID
    policy: MitigationPolicy
    agents: list[SpawnedAgent] = field(default_factory=list)
    status: str = "initializing"
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    logs: list[dict] = field(default_factory=list)

    def add_log(self, agent: str, message: str, level: str = "info"):
        self.logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "agent": agent,
            "message": message,
            "level": level,
        })

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "threat_id": str(self.threat_id),
            "policy": self.policy.value,
            "agents": [a.to_dict() for a in self.agents],
            "status": self.status,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "logs": self.logs,
        }


class MitigationOrchestratorBot:
    """
    Dynamic Mitigation Orchestrator.

    Coordinates multiple specialized agents to execute complex mitigation
    workflows based on threat severity and security policies.
    """

    # Policy definitions with rules
    POLICIES = {
        MitigationPolicy.DEFCON_1: {
            "name": "DEFCON-1 Emergency Response",
            "rules": [
                "Immediate IP blocking without confirmation",
                "Automatic rate limiting at 0 requests/second",
                "All mitigation agents spawn in parallel",
                "Notify SOC team via all channels",
                "Enable enhanced logging and packet capture",
                "Escalate to incident response automatically",
            ],
            "parallel_execution": True,
            "auto_block": True,
            "escalation_required": True,
        },
        MitigationPolicy.ACTIVE_DEFENSE: {
            "name": "Active Defense Protocol",
            "rules": [
                "IP blocking after threat verification",
                "Rate limiting at 10 requests/minute",
                "Sequential agent spawning with verification",
                "Alert SOC team via primary channel",
                "Enable detailed logging for forensics",
                "Monitor for attack pattern spread",
            ],
            "parallel_execution": False,
            "auto_block": True,
            "escalation_required": False,
        },
        MitigationPolicy.STANDARD: {
            "name": "Standard Response Procedure",
            "rules": [
                "Rate limiting at 100 requests/minute",
                "Monitor and log suspicious activity",
                "Spawn analyzer agent for threat confirmation",
                "Generate incident report",
                "Queue for SOC review if patterns persist",
            ],
            "parallel_execution": False,
            "auto_block": False,
            "escalation_required": False,
        },
        MitigationPolicy.MONITORING: {
            "name": "Monitoring & Assessment",
            "rules": [
                "Log and monitor traffic patterns",
                "No automatic blocking actions",
                "Analyze for false positive indicators",
                "Add to watchlist for 24-hour observation",
                "Generate weekly summary report",
            ],
            "parallel_execution": False,
            "auto_block": False,
            "escalation_required": False,
        },
    }

    # Agent definitions for dynamic spawning
    AGENT_DEFINITIONS = {
        "orchestrator": {
            "name": "Mitigation Orchestrator",
            "icon": "🎯",
            "actions": ["Coordinating response", "Spawning agents"],
        },
        "analyzer": {
            "name": "Threat Analyzer",
            "icon": "🔍",
            "actions": ["Analyzing threat vectors", "Confirming attack signature"],
        },
        "responder": {
            "name": "Response Planner",
            "icon": "📋",
            "actions": ["Generating response plan", "Validating actions"],
        },
        "mitigator": {
            "name": "Mitigator Agent",
            "icon": "🛡️",
            "actions": ["Executing mitigation", "Verifying effectiveness"],
        },
        "reporter": {
            "name": "Reporter Agent",
            "icon": "📊",
            "actions": ["Generating incident report", "Notifying stakeholders"],
        },
        "forensics": {
            "name": "Forensics Collector",
            "icon": "🔬",
            "actions": ["Capturing evidence", "Preserving logs"],
        },
        "escalation": {
            "name": "Escalation Agent",
            "icon": "🚨",
            "actions": ["Alerting SOC team", "Creating incident ticket"],
        },
        "monitor": {
            "name": "Monitor Agent",
            "icon": "👁️",
            "actions": ["Continuous monitoring", "Pattern detection"],
        },
    }

    def __init__(
        self,
        bot_id: str = "mitigation_orchestrator_001",
        event_callback: Optional[Callable[[str, dict], None]] = None,
    ):
        self.bot_id = bot_id
        self.bot_type = "mitigation_orchestrator"
        self._workflows: dict[UUID, MitigationWorkflow] = {}
        self._active_agents: dict[str, SpawnedAgent] = {}
        self._event_callback = event_callback

        # Statistics
        self._workflows_completed = 0
        self._workflows_failed = 0
        self._agents_spawned = 0

    def _emit_event(self, event_type: str, data: dict):
        """Emit event to callback if registered."""
        if self._event_callback:
            self._event_callback(event_type, data)

    def get_policy_for_severity(self, severity: str) -> MitigationPolicy:
        """Determine mitigation policy based on severity."""
        severity_map = {
            "critical": MitigationPolicy.DEFCON_1,
            "high": MitigationPolicy.ACTIVE_DEFENSE,
            "medium": MitigationPolicy.STANDARD,
            "low": MitigationPolicy.MONITORING,
        }
        return severity_map.get(severity.lower(), MitigationPolicy.STANDARD)

    def get_agent_sequence(
        self, policy: MitigationPolicy, action_type: str
    ) -> list[str]:
        """Get agent sequence based on policy and action type."""
        base_sequence = ["orchestrator", "analyzer", "responder", "mitigator", "reporter"]

        if policy == MitigationPolicy.DEFCON_1:
            # Add forensics and escalation for critical threats
            base_sequence.insert(2, "forensics")
            base_sequence.append("escalation")
        elif policy == MitigationPolicy.ACTIVE_DEFENSE:
            # Add monitor for high severity
            base_sequence.append("monitor")

        return base_sequence

    async def create_workflow(
        self,
        threat: Threat,
        action_type: str = "block_ip",
    ) -> MitigationWorkflow:
        """
        Create a new mitigation workflow for a threat.

        Args:
            threat: Threat to mitigate
            action_type: Type of mitigation action

        Returns:
            MitigationWorkflow instance
        """
        severity = threat.threat_level.severity.value if threat.threat_level else "medium"
        policy = self.get_policy_for_severity(severity)

        workflow = MitigationWorkflow(
            id=uuid4(),
            threat_id=threat.id,
            policy=policy,
        )

        self._workflows[workflow.id] = workflow

        workflow.add_log(
            "ORCHESTRATOR",
            f"Workflow created for threat {threat.id} with policy {policy.value}",
        )

        self._emit_event("workflow_created", workflow.to_dict())

        logger.info(
            "mitigation_workflow_created",
            workflow_id=str(workflow.id),
            threat_id=str(threat.id),
            policy=policy.value,
        )

        return workflow

    async def spawn_agent(
        self,
        workflow: MitigationWorkflow,
        agent_type: str,
    ) -> SpawnedAgent:
        """
        Dynamically spawn an agent for the workflow.

        Args:
            workflow: Parent workflow
            agent_type: Type of agent to spawn

        Returns:
            SpawnedAgent instance
        """
        agent_def = self.AGENT_DEFINITIONS.get(agent_type, {
            "name": f"{agent_type.title()} Agent",
            "icon": "🤖",
            "actions": ["Processing"],
        })

        agent = SpawnedAgent(
            id=f"{agent_type}_{uuid4().hex[:8]}",
            name=agent_def["name"],
            agent_type=agent_type,
            state=AgentState.SPAWNING,
            spawn_time=datetime.utcnow(),
            actions=agent_def["actions"].copy(),
        )

        workflow.agents.append(agent)
        self._active_agents[agent.id] = agent
        self._agents_spawned += 1

        workflow.add_log("SPAWNER", f"Agent spawned: {agent.name}")

        self._emit_event("agent_spawned", {
            "workflow_id": str(workflow.id),
            "agent": agent.to_dict(),
        })

        # Simulate spawn delay
        await asyncio.sleep(0.1)
        agent.state = AgentState.ACTIVE

        logger.info(
            "agent_spawned",
            agent_id=agent.id,
            agent_type=agent_type,
            workflow_id=str(workflow.id),
        )

        return agent

    async def execute_agent(
        self,
        workflow: MitigationWorkflow,
        agent: SpawnedAgent,
        threat: Threat,
        action_type: str,
    ) -> dict:
        """
        Execute an agent's actions.

        Args:
            workflow: Parent workflow
            agent: Agent to execute
            threat: Target threat
            action_type: Type of action

        Returns:
            Execution results
        """
        start_time = datetime.utcnow()
        agent.state = AgentState.EXECUTING

        self._emit_event("agent_executing", {
            "workflow_id": str(workflow.id),
            "agent_id": agent.id,
        })

        results = []

        for action in agent.actions:
            workflow.add_log(agent.name.upper().replace(" ", "_"), action)

            self._emit_event("agent_action", {
                "workflow_id": str(workflow.id),
                "agent_id": agent.id,
                "action": action,
            })

            # Simulate action execution
            await asyncio.sleep(0.2 + (0.3 * (hash(action) % 10) / 10))

            results.append({
                "action": action,
                "status": "success",
                "timestamp": datetime.utcnow().isoformat(),
            })

        agent.results = results
        agent.execution_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        agent.state = AgentState.COMPLETED

        self._emit_event("agent_completed", {
            "workflow_id": str(workflow.id),
            "agent_id": agent.id,
            "results": results,
        })

        logger.info(
            "agent_executed",
            agent_id=agent.id,
            execution_time_ms=agent.execution_time_ms,
        )

        return {
            "agent_id": agent.id,
            "status": "completed",
            "results": results,
            "execution_time_ms": agent.execution_time_ms,
        }

    async def run_workflow(
        self,
        threat: Threat,
        action_type: str = "block_ip",
    ) -> MitigationWorkflow:
        """
        Run a complete mitigation workflow.

        Args:
            threat: Threat to mitigate
            action_type: Type of mitigation action

        Returns:
            Completed workflow
        """
        workflow = await self.create_workflow(threat, action_type)
        policy_config = self.POLICIES[workflow.policy]
        agent_sequence = self.get_agent_sequence(workflow.policy, action_type)

        workflow.status = "running"

        try:
            if policy_config["parallel_execution"]:
                # Spawn and execute all agents in parallel
                agents = []
                for agent_type in agent_sequence:
                    agent = await self.spawn_agent(workflow, agent_type)
                    agents.append(agent)

                # Execute in parallel
                tasks = [
                    self.execute_agent(workflow, agent, threat, action_type)
                    for agent in agents
                ]
                await asyncio.gather(*tasks)
            else:
                # Sequential execution
                for agent_type in agent_sequence:
                    agent = await self.spawn_agent(workflow, agent_type)
                    await self.execute_agent(workflow, agent, threat, action_type)

            workflow.status = "completed"
            workflow.end_time = datetime.utcnow()
            workflow.add_log("ORCHESTRATOR", "Mitigation workflow completed successfully", "success")
            self._workflows_completed += 1

        except Exception as e:
            workflow.status = "failed"
            workflow.end_time = datetime.utcnow()
            workflow.add_log("ORCHESTRATOR", f"Workflow failed: {str(e)}", "error")
            self._workflows_failed += 1
            logger.error("workflow_failed", workflow_id=str(workflow.id), error=str(e))

        self._emit_event("workflow_completed", workflow.to_dict())

        return workflow

    async def spawn_additional_agents(
        self,
        workflow_id: UUID,
        agent_types: list[str],
    ) -> list[SpawnedAgent]:
        """
        Dynamically spawn additional agents for an existing workflow.

        Args:
            workflow_id: ID of existing workflow
            agent_types: Types of agents to spawn

        Returns:
            List of spawned agents
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")

        agents = []
        for agent_type in agent_types:
            agent = await self.spawn_agent(workflow, agent_type)
            agents.append(agent)

        return agents

    def get_workflow(self, workflow_id: UUID) -> Optional[MitigationWorkflow]:
        """Get workflow by ID."""
        return self._workflows.get(workflow_id)

    def get_active_workflows(self) -> list[MitigationWorkflow]:
        """Get all active workflows."""
        return [w for w in self._workflows.values() if w.status == "running"]

    def get_stats(self) -> dict:
        """Get orchestrator statistics."""
        return {
            "bot_id": self.bot_id,
            "bot_type": self.bot_type,
            "workflows_completed": self._workflows_completed,
            "workflows_failed": self._workflows_failed,
            "agents_spawned": self._agents_spawned,
            "active_workflows": len(self.get_active_workflows()),
            "total_workflows": len(self._workflows),
        }
