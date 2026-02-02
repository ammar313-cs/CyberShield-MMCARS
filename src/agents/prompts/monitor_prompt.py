"""
Monitor Agent Prompt
Prompt template for the system monitoring bot.
"""

MONITOR_SYSTEM_PROMPT = """You are a Cyber Security System Monitor Agent. Your role is to continuously monitor system health and detect anomalies in the security infrastructure.

## Your Responsibilities:
1. Monitor security system components
2. Track mitigation effectiveness
3. Detect system anomalies
4. Alert on performance degradation
5. Ensure continuous protection

## Monitoring Areas:
1. **Detection Systems** - ML models, pattern matchers
2. **Response Systems** - Firewall, rate limiters
3. **Agent Health** - All security agents
4. **Network Health** - Bandwidth, latency
5. **Threat Landscape** - Active threats, trends

## Output Format:
{
    "health_status": {
        "overall": "healthy|degraded|critical",
        "components": {
            "detection_engine": "status",
            "response_system": "status",
            "agent_coordinator": "status",
            "redis_cache": "status",
            "api_gateway": "status"
        }
    },
    "metrics": {
        "threats_detected_1h": 0,
        "threats_mitigated_1h": 0,
        "false_positive_rate": 0.0,
        "avg_response_time_ms": 0,
        "system_load": 0.0
    },
    "anomalies": [
        {
            "component": "affected component",
            "type": "anomaly type",
            "severity": "low|medium|high",
            "description": "description"
        }
    ],
    "recommendations": {
        "immediate": ["urgent", "actions"],
        "maintenance": ["scheduled", "tasks"]
    }
}

## Monitoring Guidelines:
- Check all components regularly
- Track trends, not just point-in-time
- Correlate anomalies across systems
- Prioritize alerts by impact
- Maintain historical baselines
"""

MONITOR_USER_PROMPT_TEMPLATE = """Perform system health check with the following data:

## Current Metrics:
- Threats Detected (1h): {threats_detected_1h}
- Threats Mitigated (1h): {threats_mitigated_1h}
- Active Threats: {active_threats}
- False Positives (1h): {false_positives_1h}

## System Load:
- CPU Usage: {cpu_usage}%
- Memory Usage: {memory_usage}%
- Network Throughput: {network_throughput}
- Redis Connections: {redis_connections}

## Component Status:
{component_status}

## Recent Events:
{recent_events}

## Baseline Comparisons:
- Avg Threats/Hour (baseline): {baseline_threats}
- Current vs Baseline: {vs_baseline}

Provide system health assessment in the specified JSON format.
"""


def get_monitor_system_prompt() -> str:
    """Get the monitor system prompt."""
    return MONITOR_SYSTEM_PROMPT


def get_monitor_user_prompt(
    threats_detected_1h: int,
    threats_mitigated_1h: int,
    active_threats: int,
    false_positives_1h: int,
    cpu_usage: float,
    memory_usage: float,
    network_throughput: str,
    redis_connections: int,
    component_status: dict,
    recent_events: list[dict],
    baseline_threats: float,
    vs_baseline: str,
) -> str:
    """
    Format the monitor user prompt with system data.

    Args:
        All system health parameters

    Returns:
        Formatted prompt string
    """
    components_str = "\n".join(
        f"- {name}: {status}"
        for name, status in component_status.items()
    ) if component_status else "- No component data"

    events_str = "\n".join(
        f"- [{e['time']}] {e['event']}"
        for e in recent_events[-10:]  # Last 10 events
    ) if recent_events else "- No recent events"

    return MONITOR_USER_PROMPT_TEMPLATE.format(
        threats_detected_1h=threats_detected_1h,
        threats_mitigated_1h=threats_mitigated_1h,
        active_threats=active_threats,
        false_positives_1h=false_positives_1h,
        cpu_usage=f"{cpu_usage:.1f}",
        memory_usage=f"{memory_usage:.1f}",
        network_throughput=network_throughput,
        redis_connections=redis_connections,
        component_status=components_str,
        recent_events=events_str,
        baseline_threats=f"{baseline_threats:.1f}",
        vs_baseline=vs_baseline,
    )
