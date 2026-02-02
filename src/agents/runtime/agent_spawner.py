"""
Agent Spawner
Dynamically spawns specialized agents based on threat context.

Similar to Claude Code's Task tool for launching subagents with appropriate models.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Any
from uuid import UUID
import structlog

from src.agents.llm.claude_client import (
    get_agent_client,
    get_model_for_agent,
    ORCHESTRATOR_MODEL,
    AGENT_MODEL,
)
from src.domain.entities.threat import Threat

logger = structlog.get_logger(__name__)


@dataclass
class AgentTask:
    """Task definition for spawning an agent."""

    agent_type: str
    threat: Threat
    context: dict
    priority: int = 1


@dataclass
class AgentResult:
    """Result from a spawned agent."""

    agent_type: str
    model_used: str
    success: bool
    result: Any
    error: Optional[str] = None
    execution_time_ms: float = 0
    tokens_used: dict = None

    def to_dict(self) -> dict:
        return {
            "agent_type": self.agent_type,
            "model_used": self.model_used,
            "success": self.success,
            "result": self.result if isinstance(self.result, dict) else str(self.result),
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
            "tokens_used": self.tokens_used or {},
        }


class AgentSpawner:
    """
    Dynamically spawns specialized agents based on threat context.

    Multi-model architecture:
    - Orchestrator decisions use Sonnet 4.5 (complex reasoning)
    - Sub-agents use Haiku (fast, cost-effective)

    Similar to Claude Code's Task tool for launching subagents.
    """

    def __init__(self):
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._results_cache: dict[str, AgentResult] = {}

    async def spawn_analysis_agent(
        self,
        threat: Threat,
        features: Optional[dict] = None,
        predictions: Optional[dict] = None,
    ) -> AgentResult:
        """
        Spawn lightweight analyzer for quick threat classification.

        Uses Haiku model for fast execution.
        """
        from src.agents.bots.analyzer_bot import AnalyzerBot

        start_time = datetime.utcnow()
        model = get_model_for_agent("analyzer")

        try:
            client = get_agent_client("analyzer")
            analyzer = AnalyzerBot(
                bot_id=f"analyzer_{threat.id.hex[:8]}",
                use_llm=True,
                claude_client=client,
            )

            result = await analyzer.analyze(
                threat=threat,
                features=features,
                predictions=predictions or {},
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(
                "analysis_agent_completed",
                threat_id=str(threat.id),
                model=model,
                execution_time_ms=execution_time,
            )

            return AgentResult(
                agent_type="analyzer",
                model_used=model,
                success=True,
                result=result.to_dict() if hasattr(result, "to_dict") else result,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            logger.error(
                "analysis_agent_failed",
                threat_id=str(threat.id),
                error=str(e),
            )
            return AgentResult(
                agent_type="analyzer",
                model_used=model,
                success=False,
                result=None,
                error=str(e),
                execution_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
            )

    async def spawn_response_agent(
        self,
        threat: Threat,
        analysis: dict,
    ) -> AgentResult:
        """
        Spawn response planner based on threat type.

        Uses Haiku model for fast action planning.
        """
        from src.agents.bots.responder_bot import ResponderBot
        from src.agents.bots.analyzer_bot import AnalysisResult

        start_time = datetime.utcnow()
        model = get_model_for_agent("responder")

        try:
            client = get_agent_client("responder")
            responder = ResponderBot(
                bot_id=f"responder_{threat.id.hex[:8]}",
                use_llm=True,
                claude_client=client,
            )

            # Reconstruct AnalysisResult from dict
            analysis_result = AnalysisResult(
                threat_id=threat.id,
                attack_type=analysis.get("attack_type", "unknown"),
                severity=analysis.get("severity", "medium"),
                confidence=analysis.get("confidence", 0.5),
                summary=analysis.get("summary", ""),
                indicators=analysis.get("indicators", []),
                attack_vector=analysis.get("attack_vector", ""),
                potential_impact=analysis.get("potential_impact", ""),
                priority=analysis.get("priority", "medium"),
                suggested_actions=analysis.get("suggested_actions", []),
                escalation_needed=analysis.get("escalation_needed", False),
                analysis_time_ms=analysis.get("analysis_time_ms", 0),
            )

            result = await responder.plan_response(
                threat=threat,
                analysis=analysis_result,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(
                "response_agent_completed",
                threat_id=str(threat.id),
                model=model,
                execution_time_ms=execution_time,
            )

            return AgentResult(
                agent_type="responder",
                model_used=model,
                success=True,
                result=result.to_dict() if hasattr(result, "to_dict") else result,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            logger.error(
                "response_agent_failed",
                threat_id=str(threat.id),
                error=str(e),
            )
            return AgentResult(
                agent_type="responder",
                model_used=model,
                success=False,
                result=None,
                error=str(e),
                execution_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
            )

    async def spawn_mitigation_agent(
        self,
        threat: Threat,
        response_plan: dict,
    ) -> AgentResult:
        """
        Spawn mitigation executor.

        Uses Haiku model for coordinating action execution.
        """
        from src.agents.bots.mitigator_bot import MitigatorBot

        start_time = datetime.utcnow()
        model = get_model_for_agent("mitigator")

        try:
            mitigator = MitigatorBot(
                bot_id=f"mitigator_{threat.id.hex[:8]}",
            )

            result = await mitigator.execute(response_plan)

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(
                "mitigation_agent_completed",
                threat_id=str(threat.id),
                model=model,
                execution_time_ms=execution_time,
            )

            return AgentResult(
                agent_type="mitigator",
                model_used=model,
                success=result.success if hasattr(result, "success") else True,
                result=result.to_dict() if hasattr(result, "to_dict") else result,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            logger.error(
                "mitigation_agent_failed",
                threat_id=str(threat.id),
                error=str(e),
            )
            return AgentResult(
                agent_type="mitigator",
                model_used=model,
                success=False,
                result=None,
                error=str(e),
                execution_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
            )

    async def spawn_reporter_agent(
        self,
        threat: Threat,
        analysis: dict,
        response_plan: dict,
        mitigation_result: dict,
    ) -> AgentResult:
        """
        Spawn report generator.

        Uses Haiku model for generating alerts and reports.
        """
        from src.agents.bots.reporter_bot import ReporterBot

        start_time = datetime.utcnow()
        model = get_model_for_agent("reporter")

        try:
            client = get_agent_client("reporter")
            reporter = ReporterBot(
                bot_id=f"reporter_{threat.id.hex[:8]}",
                claude_client=client,
            )

            result = await reporter.generate_incident_report(
                threat=threat,
                analysis=analysis,
                response_plan=response_plan,
                mitigation_result=mitigation_result,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            logger.info(
                "reporter_agent_completed",
                threat_id=str(threat.id),
                model=model,
                execution_time_ms=execution_time,
            )

            return AgentResult(
                agent_type="reporter",
                model_used=model,
                success=True,
                result={"report": result},
                execution_time_ms=execution_time,
            )

        except Exception as e:
            logger.error(
                "reporter_agent_failed",
                threat_id=str(threat.id),
                error=str(e),
            )
            return AgentResult(
                agent_type="reporter",
                model_used=model,
                success=False,
                result=None,
                error=str(e),
                execution_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000,
            )

    async def spawn_parallel_agents(
        self,
        tasks: list[AgentTask],
    ) -> list[AgentResult]:
        """
        Run multiple agents in parallel for efficiency.

        Useful when multiple independent analyses can run simultaneously.
        """
        async def run_task(task: AgentTask) -> AgentResult:
            if task.agent_type == "analyzer":
                return await self.spawn_analysis_agent(
                    threat=task.threat,
                    features=task.context.get("features"),
                    predictions=task.context.get("predictions"),
                )
            elif task.agent_type == "responder":
                return await self.spawn_response_agent(
                    threat=task.threat,
                    analysis=task.context.get("analysis", {}),
                )
            elif task.agent_type == "mitigator":
                return await self.spawn_mitigation_agent(
                    threat=task.threat,
                    response_plan=task.context.get("response_plan", {}),
                )
            elif task.agent_type == "reporter":
                return await self.spawn_reporter_agent(
                    threat=task.threat,
                    analysis=task.context.get("analysis", {}),
                    response_plan=task.context.get("response_plan", {}),
                    mitigation_result=task.context.get("mitigation_result", {}),
                )
            else:
                return AgentResult(
                    agent_type=task.agent_type,
                    model_used="none",
                    success=False,
                    result=None,
                    error=f"Unknown agent type: {task.agent_type}",
                )

        # Sort by priority and run in parallel
        sorted_tasks = sorted(tasks, key=lambda t: t.priority)
        results = await asyncio.gather(
            *[run_task(task) for task in sorted_tasks],
            return_exceptions=True,
        )

        # Convert exceptions to AgentResult
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(AgentResult(
                    agent_type=sorted_tasks[i].agent_type,
                    model_used="none",
                    success=False,
                    result=None,
                    error=str(result),
                ))
            else:
                final_results.append(result)

        return final_results

    async def run_sequential_pipeline(
        self,
        threat: Threat,
        features: Optional[dict] = None,
        predictions: Optional[dict] = None,
    ) -> dict[str, AgentResult]:
        """
        Run the full agent pipeline sequentially.

        Returns results from each stage.
        """
        results = {}

        # Stage 1: Analysis
        analysis_result = await self.spawn_analysis_agent(
            threat=threat,
            features=features,
            predictions=predictions,
        )
        results["analyzer"] = analysis_result

        if not analysis_result.success:
            return results

        # Stage 2: Response Planning
        response_result = await self.spawn_response_agent(
            threat=threat,
            analysis=analysis_result.result,
        )
        results["responder"] = response_result

        if not response_result.success:
            return results

        # Stage 3: Mitigation
        mitigation_result = await self.spawn_mitigation_agent(
            threat=threat,
            response_plan=response_result.result,
        )
        results["mitigator"] = mitigation_result

        # Stage 4: Reporting (even if mitigation partially failed)
        reporter_result = await self.spawn_reporter_agent(
            threat=threat,
            analysis=analysis_result.result,
            response_plan=response_result.result,
            mitigation_result=mitigation_result.result or {},
        )
        results["reporter"] = reporter_result

        return results

    def get_model_info(self) -> dict:
        """Get information about the models used by each agent type."""
        return {
            "orchestrator": {
                "model": ORCHESTRATOR_MODEL,
                "purpose": "Complex decisions, escalation, threat correlation",
            },
            "analyzer": {
                "model": AGENT_MODEL,
                "purpose": "Fast threat classification",
            },
            "responder": {
                "model": AGENT_MODEL,
                "purpose": "Action planning",
            },
            "mitigator": {
                "model": AGENT_MODEL,
                "purpose": "Execution coordination",
            },
            "reporter": {
                "model": AGENT_MODEL,
                "purpose": "Alert generation",
            },
        }


# Global spawner instance
_spawner: Optional[AgentSpawner] = None


def get_spawner() -> AgentSpawner:
    """Get the global agent spawner instance."""
    global _spawner
    if _spawner is None:
        _spawner = AgentSpawner()
    return _spawner
