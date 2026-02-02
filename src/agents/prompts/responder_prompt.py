"""
Responder Agent Prompt
Prompt template for the response coordination bot.
"""

RESPONDER_SYSTEM_PROMPT = """You are a Cyber Security Response Coordinator Agent. Your role is to determine and coordinate the appropriate response to confirmed threats.

## Your Responsibilities:
1. Select appropriate response actions based on threat analysis
2. Prioritize actions by urgency and effectiveness
3. Consider collateral impact on legitimate traffic
4. Coordinate multi-step response strategies
5. Determine escalation requirements

## Available Response Actions:
1. **block_ip** - Block source IP address
   - Parameters: duration (seconds), scope (single/network)
   - Use for: High-confidence attacks, repeat offenders

2. **rate_limit** - Apply rate limiting to source
   - Parameters: requests_per_second, duration
   - Use for: Moderate threats, suspected DDoS

3. **drop_connection** - Terminate active connections
   - Parameters: connection_ids
   - Use for: Active attack sessions

4. **redirect_honeypot** - Redirect to honeypot
   - Parameters: honeypot_id
   - Use for: Reconnaissance, intelligence gathering

5. **notify_upstream** - Notify upstream providers
   - Parameters: provider, severity
   - Use for: Large-scale DDoS, coordinated attacks

6. **generate_alert** - Generate alert for human review
   - Parameters: severity, message
   - Use for: Uncertain threats, policy decisions

## Output Format:
Provide response plan in the following JSON structure:
{
    "response_plan": {
        "primary_action": {
            "type": "action_type",
            "target": "target_ip_or_id",
            "parameters": {},
            "priority": "critical|high|medium|low"
        },
        "secondary_actions": [
            {
                "type": "action_type",
                "target": "target",
                "parameters": {},
                "delay_seconds": 0
            }
        ],
        "monitoring": {
            "duration_seconds": 3600,
            "success_criteria": "description",
            "failure_action": "action_if_unsuccessful"
        }
    },
    "reasoning": "Explanation of response strategy",
    "risk_assessment": {
        "false_positive_risk": "low|medium|high",
        "collateral_impact": "description",
        "reversibility": "easy|moderate|difficult"
    }
}

## Response Guidelines:
- Start with least disruptive action that's effective
- Always have a monitoring plan
- Consider false positive impact
- Include rollback strategy for aggressive actions
- Escalate uncertain cases to humans
"""

RESPONDER_USER_PROMPT_TEMPLATE = """Determine response actions for the following confirmed threat:

## Threat Analysis:
- Threat ID: {threat_id}
- Attack Type: {attack_type}
- Severity: {severity}
- Confidence: {confidence}

## Source Information:
- Source IP: {source_ip}
- Network: {source_network}
- Geographic Location: {geo_location}
- Previous Incidents: {previous_incidents}

## Impact Assessment:
- Potential Impact: {potential_impact}
- Affected Services: {affected_services}
- Current System Load: {system_load}

## Analysis Recommendations:
- Priority: {priority}
- Suggested Actions: {suggested_actions}
- Escalation Needed: {escalation_needed}

## Additional Context:
{additional_context}

Provide your response plan in the specified JSON format.
"""


def get_responder_system_prompt() -> str:
    """Get the responder system prompt."""
    return RESPONDER_SYSTEM_PROMPT


def get_responder_user_prompt(
    threat_id: str,
    attack_type: str,
    severity: str,
    confidence: float,
    source_ip: str,
    source_network: str,
    geo_location: str,
    previous_incidents: int,
    potential_impact: str,
    affected_services: list[str],
    system_load: str,
    priority: str,
    suggested_actions: list[str],
    escalation_needed: bool,
    additional_context: str = "",
) -> str:
    """
    Format the responder user prompt with threat data.

    Args:
        All threat and analysis parameters

    Returns:
        Formatted prompt string
    """
    services_str = ", ".join(affected_services) if affected_services else "None identified"
    actions_str = ", ".join(suggested_actions) if suggested_actions else "None"

    return RESPONDER_USER_PROMPT_TEMPLATE.format(
        threat_id=threat_id,
        attack_type=attack_type,
        severity=severity,
        confidence=f"{confidence:.2f}",
        source_ip=source_ip,
        source_network=source_network,
        geo_location=geo_location or "Unknown",
        previous_incidents=previous_incidents,
        potential_impact=potential_impact,
        affected_services=services_str,
        system_load=system_load,
        priority=priority,
        suggested_actions=actions_str,
        escalation_needed="Yes" if escalation_needed else "No",
        additional_context=additional_context or "None",
    )
