"""
Analyzer Agent Prompt
Prompt template for the threat analysis bot.
"""

ANALYZER_SYSTEM_PROMPT = """You are a Cyber Security Threat Analyzer Agent. Your role is to analyze detected threats and provide detailed assessment.

## Your Responsibilities:
1. Analyze traffic patterns and anomaly scores
2. Classify the attack type and severity
3. Identify attack vectors and techniques
4. Assess potential impact and risk level
5. Recommend response priority

## Input Format:
You will receive threat data including:
- Source IP and geographic information
- Traffic statistics (packets/sec, bytes, connections)
- ML model predictions (anomaly scores, pattern matches)
- Feature indicators (SYN ratio, port scan score, etc.)

## Output Format:
Provide analysis in the following JSON structure:
{
    "classification": {
        "attack_type": "ddos|syn_flood|port_scan|slowloris|unknown",
        "confidence": 0.0-1.0,
        "severity": "low|medium|high|critical"
    },
    "analysis": {
        "summary": "Brief description of the threat",
        "indicators": ["list", "of", "key", "indicators"],
        "attack_vector": "Description of attack method",
        "potential_impact": "Assessment of potential damage"
    },
    "recommendations": {
        "priority": "immediate|high|medium|low",
        "suggested_actions": ["list", "of", "recommended", "actions"],
        "escalation_needed": true|false
    }
}

## Analysis Guidelines:
- Consider multiple indicators before classifying
- Account for false positive likelihood
- Prioritize based on potential impact
- Be conservative with critical severity ratings
"""

ANALYZER_USER_PROMPT_TEMPLATE = """Analyze the following threat detection:

## Threat Information:
- Threat ID: {threat_id}
- Source IP: {source_ip}
- Target IP: {target_ip}
- Target Port: {target_port}
- Detection Time: {detection_time}

## Traffic Statistics:
- Packets per second: {packets_per_second}
- Bytes per second: {bytes_per_second}
- Unique source IPs: {unique_source_ips}
- Connection count: {connection_count}

## ML Predictions:
- Anomaly Score: {anomaly_score}
- Volume Score: {volume_score}
- Pattern Score: {pattern_score}
- Overall Threat Score: {threat_score}

## Feature Indicators:
- SYN Ratio: {syn_ratio}
- Port Scan Score: {port_scan_score}
- Top Source IP Ratio: {top_source_ip_ratio}
- Source IP Entropy: {source_ip_entropy}

## Detected Patterns:
{detected_patterns}

Provide your threat analysis in the specified JSON format.
"""


def get_analyzer_system_prompt() -> str:
    """Get the analyzer system prompt."""
    return ANALYZER_SYSTEM_PROMPT


def get_analyzer_user_prompt(
    threat_id: str,
    source_ip: str,
    target_ip: str,
    target_port: int,
    detection_time: str,
    packets_per_second: float,
    bytes_per_second: float,
    unique_source_ips: int,
    connection_count: int,
    anomaly_score: float,
    volume_score: float,
    pattern_score: float,
    threat_score: float,
    syn_ratio: float,
    port_scan_score: float,
    top_source_ip_ratio: float,
    source_ip_entropy: float,
    detected_patterns: list[str],
) -> str:
    """
    Format the analyzer user prompt with threat data.

    Args:
        All threat-related parameters

    Returns:
        Formatted prompt string
    """
    patterns_str = "\n".join(f"- {p}" for p in detected_patterns) if detected_patterns else "None detected"

    return ANALYZER_USER_PROMPT_TEMPLATE.format(
        threat_id=threat_id,
        source_ip=source_ip,
        target_ip=target_ip or "Unknown",
        target_port=target_port or "Unknown",
        detection_time=detection_time,
        packets_per_second=f"{packets_per_second:.2f}",
        bytes_per_second=f"{bytes_per_second:.2f}",
        unique_source_ips=unique_source_ips,
        connection_count=connection_count,
        anomaly_score=f"{anomaly_score:.3f}",
        volume_score=f"{volume_score:.3f}",
        pattern_score=f"{pattern_score:.3f}",
        threat_score=f"{threat_score:.3f}",
        syn_ratio=f"{syn_ratio:.3f}",
        port_scan_score=f"{port_scan_score:.3f}",
        top_source_ip_ratio=f"{top_source_ip_ratio:.3f}",
        source_ip_entropy=f"{source_ip_entropy:.3f}",
        detected_patterns=patterns_str,
    )
