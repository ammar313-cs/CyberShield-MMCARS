"""
Claude API Client
Wrapper for Anthropic Claude API for AI agent communications.

Multi-Model Architecture:
- Orchestrator uses Sonnet 4.5 for complex decisions (escalation, correlation)
- Sub-agents use Haiku for fast, cost-effective execution
"""

import os
import json
from typing import Optional
from dataclasses import dataclass
from enum import Enum
import structlog
import anthropic

logger = structlog.get_logger(__name__)


class ModelTier(Enum):
    """Model tiers for different agent types."""
    ORCHESTRATOR = "orchestrator"
    AGENT = "agent"


# Model constants
ORCHESTRATOR_MODEL = "claude-sonnet-4-20250514"  # Complex reasoning, escalation decisions
AGENT_MODEL = "claude-3-5-haiku-20241022"  # Fast, cost-effective for sub-agents

# Token limits per tier
ORCHESTRATOR_MAX_TOKENS = 4096
AGENT_MAX_TOKENS = 2048


@dataclass
class LLMResponse:
    """Response from LLM."""

    content: str
    model: str
    usage: dict
    stop_reason: str
    raw_response: Optional[dict] = None

    def parse_json(self) -> Optional[dict]:
        """Attempt to parse response as JSON."""
        try:
            # Try to extract JSON from markdown code blocks
            content = self.content
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                content = content[start:end].strip()
            elif "```" in content:
                start = content.find("```") + 3
                end = content.find("```", start)
                content = content[start:end].strip()

            return json.loads(content)
        except json.JSONDecodeError:
            logger.warning("failed_to_parse_json", content=self.content[:200])
            return None


class ClaudeClient:
    """
    Claude API Client for AI agent communications.

    Provides structured access to Claude for threat analysis,
    response coordination, and report generation.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
    ):
        self.api_key = api_key or os.getenv("CLAUDE_API_KEY")
        if not self.api_key:
            raise ValueError("CLAUDE_API_KEY not provided or found in environment")

        self.model = model
        self.max_tokens = max_tokens
        self.client = anthropic.Anthropic(api_key=self.api_key)

        logger.info(
            "claude_client_initialized",
            model=self.model,
            max_tokens=self.max_tokens,
        )

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: Optional[int] = None,
        temperature: float = 0.3,
    ) -> LLMResponse:
        """
        Generate a response from Claude.

        Args:
            system_prompt: System prompt defining agent behavior
            user_prompt: User message with specific request
            max_tokens: Optional override for max tokens
            temperature: Sampling temperature (lower = more focused)

        Returns:
            LLMResponse with generated content
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
            )

            content = response.content[0].text if response.content else ""

            llm_response = LLMResponse(
                content=content,
                model=response.model,
                usage={
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
                stop_reason=response.stop_reason,
                raw_response={
                    "id": response.id,
                    "type": response.type,
                },
            )

            logger.debug(
                "claude_response_generated",
                model=response.model,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            )

            return llm_response

        except anthropic.APIError as e:
            logger.error("claude_api_error", error=str(e))
            raise

    async def analyze_threat(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> Optional[dict]:
        """
        Analyze a threat and return structured JSON response.

        Uses lower temperature for consistent analysis results.
        """
        response = await self.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.2,
        )
        return response.parse_json()

    async def coordinate_response(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> Optional[dict]:
        """
        Coordinate threat response and return action plan.
        """
        response = await self.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.3,
        )
        return response.parse_json()

    async def generate_report(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """
        Generate a human-readable report.

        Uses slightly higher temperature for more natural text.
        """
        response = await self.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=0.5,
        )
        return response.content


# Global client instance (lazy initialization)
_claude_client: Optional[ClaudeClient] = None


def get_claude_client() -> ClaudeClient:
    """Get or create the global Claude client."""
    global _claude_client
    if _claude_client is None:
        _claude_client = ClaudeClient()
    return _claude_client


def init_claude_client(
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514",
) -> ClaudeClient:
    """Initialize the global Claude client with custom settings."""
    global _claude_client
    _claude_client = ClaudeClient(api_key=api_key, model=model)
    return _claude_client


# Agent-specific client cache
_agent_clients: dict[str, ClaudeClient] = {}


def get_agent_client(agent_type: str) -> ClaudeClient:
    """
    Get appropriately-sized model for agent type.

    Multi-model architecture similar to Claude Code:
    - Orchestrator: Uses Sonnet 4.5 for complex decisions
    - Sub-agents: Use Haiku for fast execution

    Args:
        agent_type: One of "orchestrator", "analyzer", "responder",
                   "mitigator", "reporter", or "monitor"

    Returns:
        ClaudeClient configured with the appropriate model
    """
    global _agent_clients

    if agent_type in _agent_clients:
        return _agent_clients[agent_type]

    if agent_type == "orchestrator":
        client = ClaudeClient(
            model=ORCHESTRATOR_MODEL,
            max_tokens=ORCHESTRATOR_MAX_TOKENS,
        )
        logger.info(
            "orchestrator_client_created",
            model=ORCHESTRATOR_MODEL,
            purpose="complex_decisions",
        )
    else:
        client = ClaudeClient(
            model=AGENT_MODEL,
            max_tokens=AGENT_MAX_TOKENS,
        )
        logger.info(
            "agent_client_created",
            agent_type=agent_type,
            model=AGENT_MODEL,
            purpose="fast_execution",
        )

    _agent_clients[agent_type] = client
    return client


def get_model_for_agent(agent_type: str) -> str:
    """Get the model name for an agent type."""
    if agent_type == "orchestrator":
        return ORCHESTRATOR_MODEL
    return AGENT_MODEL
