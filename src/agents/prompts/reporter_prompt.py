"""
Reporter Agent Prompt
Prompt template for the alert and report generation bot.
"""

REPORTER_SYSTEM_PROMPT = """You are a Cyber Security Reporter Agent. Your role is to generate alerts, reports, and communications about security incidents.

## Your Responsibilities:
1. Generate real-time alerts for detected threats
2. Create incident reports for documentation
3. Prepare executive summaries
4. Generate technical reports for security teams
5. Create compliance documentation

## Alert Types:
1. **Real-time Alert** - Immediate notification of active threat
2. **Incident Report** - Detailed post-incident documentation
3. **Executive Summary** - High-level overview for management
4. **Technical Report** - Detailed analysis for security team
5. **Compliance Report** - Regulatory documentation

## Output Format for Alerts:
{
    "alert": {
        "alert_id": "unique_id",
        "severity": "critical|high|medium|low|info",
        "title": "Brief alert title",
        "summary": "One paragraph summary",
        "timestamp": "ISO timestamp"
    },
    "details": {
        "threat_type": "attack type",
        "source": "source IP/network",
        "target": "target system/service",
        "status": "active|mitigated|monitoring",
        "actions_taken": ["list", "of", "actions"]
    },
    "recommendations": {
        "immediate": ["immediate", "actions"],
        "short_term": ["short", "term", "actions"],
        "long_term": ["long", "term", "improvements"]
    },
    "metrics": {
        "detection_time": "time to detect",
        "response_time": "time to respond",
        "mitigation_time": "time to mitigate",
        "impact_duration": "total impact time"
    }
}

## Reporting Guidelines:
- Be clear and concise
- Lead with the most critical information
- Use actionable language
- Include relevant metrics
- Tailor detail level to audience
- Ensure accuracy over speed
"""

REPORTER_USER_PROMPT_TEMPLATE = """Generate an alert/report for the following security incident:

## Incident Overview:
- Incident ID: {incident_id}
- Report Type: {report_type}
- Severity: {severity}
- Status: {status}

## Threat Details:
- Attack Type: {attack_type}
- Source IP: {source_ip}
- Target: {target}
- Detection Time: {detection_time}
- Duration: {duration}

## Impact Assessment:
- Affected Services: {affected_services}
- Traffic Impact: {traffic_impact}
- Data Impact: {data_impact}

## Response Summary:
- Actions Taken: {actions_taken}
- Current Status: {current_status}
- Mitigation Effectiveness: {effectiveness}

## Timeline:
{timeline}

## Additional Context:
{additional_context}

Generate the appropriate report in the specified JSON format.
"""


def get_reporter_system_prompt() -> str:
    """Get the reporter system prompt."""
    return REPORTER_SYSTEM_PROMPT


def get_reporter_user_prompt(
    incident_id: str,
    report_type: str,
    severity: str,
    status: str,
    attack_type: str,
    source_ip: str,
    target: str,
    detection_time: str,
    duration: str,
    affected_services: list[str],
    traffic_impact: str,
    data_impact: str,
    actions_taken: list[str],
    current_status: str,
    effectiveness: str,
    timeline: list[dict],
    additional_context: str = "",
) -> str:
    """
    Format the reporter user prompt with incident data.

    Args:
        All incident and report parameters

    Returns:
        Formatted prompt string
    """
    services_str = ", ".join(affected_services) if affected_services else "None identified"
    actions_str = "\n".join(f"- {a}" for a in actions_taken) if actions_taken else "- None"
    timeline_str = "\n".join(
        f"- [{e['time']}] {e['event']}"
        for e in timeline
    ) if timeline else "- No timeline available"

    return REPORTER_USER_PROMPT_TEMPLATE.format(
        incident_id=incident_id,
        report_type=report_type,
        severity=severity,
        status=status,
        attack_type=attack_type,
        source_ip=source_ip,
        target=target,
        detection_time=detection_time,
        duration=duration,
        affected_services=services_str,
        traffic_impact=traffic_impact,
        data_impact=data_impact,
        actions_taken=actions_str,
        current_status=current_status,
        effectiveness=effectiveness,
        timeline=timeline_str,
        additional_context=additional_context or "None",
    )
