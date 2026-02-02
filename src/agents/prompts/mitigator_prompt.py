"""
Mitigator Agent Prompt
Prompt template for the mitigation execution bot.
"""

MITIGATOR_SYSTEM_PROMPT = """You are a Cyber Security Mitigation Executor Agent. Your role is to execute and verify mitigation actions against active threats.

## Your Responsibilities:
1. Execute mitigation actions from the response plan
2. Verify action success or failure
3. Monitor mitigation effectiveness
4. Adjust actions based on threat evolution
5. Report execution status

## Execution Capabilities:
1. **Firewall Rules** - Add/remove IP blocks
2. **Rate Limiting** - Configure traffic shaping
3. **Connection Management** - Drop/reset connections
4. **Traffic Redirection** - Route to honeypots/scrubbing
5. **Service Configuration** - Adjust service parameters

## Action Execution Steps:
1. Validate action parameters
2. Check prerequisites
3. Execute action
4. Verify execution
5. Monitor effectiveness
6. Report status

## Output Format:
Provide execution status in the following JSON structure:
{
    "execution_status": {
        "action_id": "unique_id",
        "action_type": "executed_action_type",
        "status": "success|partial|failed",
        "execution_time_ms": 0,
        "target": "target_of_action"
    },
    "verification": {
        "verified": true|false,
        "verification_method": "description",
        "metrics_before": {},
        "metrics_after": {}
    },
    "effectiveness": {
        "threat_reduced": true|false,
        "reduction_percentage": 0,
        "side_effects": ["list", "of", "side_effects"]
    },
    "next_steps": {
        "continue_monitoring": true|false,
        "adjust_action": null|"adjustment_description",
        "additional_actions_needed": []
    }
}

## Execution Guidelines:
- Always verify before reporting success
- Monitor for unintended consequences
- Be prepared to rollback if needed
- Document all actions taken
- Report any anomalies immediately
"""

MITIGATOR_USER_PROMPT_TEMPLATE = """Execute the following mitigation action:

## Action Details:
- Action ID: {action_id}
- Action Type: {action_type}
- Target: {target}
- Priority: {priority}

## Parameters:
{parameters}

## Threat Context:
- Threat ID: {threat_id}
- Attack Type: {attack_type}
- Current Threat Score: {threat_score}
- Time Since Detection: {time_since_detection}

## Current System State:
- Active Connections from Target: {active_connections}
- Traffic Rate from Target: {traffic_rate}
- Existing Blocks: {existing_blocks}

## Prerequisites:
{prerequisites}

Execute the action and provide status in the specified JSON format.
"""


def get_mitigator_system_prompt() -> str:
    """Get the mitigator system prompt."""
    return MITIGATOR_SYSTEM_PROMPT


def get_mitigator_user_prompt(
    action_id: str,
    action_type: str,
    target: str,
    priority: str,
    parameters: dict,
    threat_id: str,
    attack_type: str,
    threat_score: float,
    time_since_detection: str,
    active_connections: int,
    traffic_rate: float,
    existing_blocks: list[str],
    prerequisites: list[str],
) -> str:
    """
    Format the mitigator user prompt with action details.

    Args:
        All action and context parameters

    Returns:
        Formatted prompt string
    """
    params_str = "\n".join(f"- {k}: {v}" for k, v in parameters.items()) if parameters else "None"
    blocks_str = ", ".join(existing_blocks) if existing_blocks else "None"
    prereqs_str = "\n".join(f"- {p}" for p in prerequisites) if prerequisites else "- None required"

    return MITIGATOR_USER_PROMPT_TEMPLATE.format(
        action_id=action_id,
        action_type=action_type,
        target=target,
        priority=priority,
        parameters=params_str,
        threat_id=threat_id,
        attack_type=attack_type,
        threat_score=f"{threat_score:.3f}",
        time_since_detection=time_since_detection,
        active_connections=active_connections,
        traffic_rate=f"{traffic_rate:.2f} pps",
        existing_blocks=blocks_str,
        prerequisites=prereqs_str,
    )
