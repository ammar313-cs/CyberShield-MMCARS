"""Agent Prompts - LLM prompt templates for each agent."""

from src.agents.prompts.analyzer_prompt import (
    get_analyzer_system_prompt,
    get_analyzer_user_prompt,
)
from src.agents.prompts.responder_prompt import (
    get_responder_system_prompt,
    get_responder_user_prompt,
)
from src.agents.prompts.mitigator_prompt import (
    get_mitigator_system_prompt,
    get_mitigator_user_prompt,
)
from src.agents.prompts.reporter_prompt import (
    get_reporter_system_prompt,
    get_reporter_user_prompt,
)
from src.agents.prompts.monitor_prompt import (
    get_monitor_system_prompt,
    get_monitor_user_prompt,
)

__all__ = [
    "get_analyzer_system_prompt",
    "get_analyzer_user_prompt",
    "get_responder_system_prompt",
    "get_responder_user_prompt",
    "get_mitigator_system_prompt",
    "get_mitigator_user_prompt",
    "get_reporter_system_prompt",
    "get_reporter_user_prompt",
    "get_monitor_system_prompt",
    "get_monitor_user_prompt",
]
