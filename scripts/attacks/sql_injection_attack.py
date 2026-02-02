#!/usr/bin/env python3
"""
SQL Injection Attack Simulation
Simulates SQL injection attack patterns in HTTP traffic.
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
║           SQL INJECTION ATTACK SIMULATION                      ║
║           Database Exploitation via HTTP Requests              ║
╚═══════════════════════════════════════════════════════════════╝
    """
    )


async def simulate_sql_injection(
    attacker_ip: str = None,
    target_ip: str = "10.0.0.1",
    num_attempts: int = 100,
):
    """
    Simulate SQL Injection attack.

    Characteristics:
    - HTTP/HTTPS traffic (ports 80, 443)
    - Larger packet sizes (containing SQL payloads)
    - Multiple requests to same endpoint
    - Varied packet sizes (different payloads)
    """
    if attacker_ip is None:
        attacker_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"

    print(f"\n[*] Simulating SQL Injection Attack")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Target: {target_ip}:80/443")
    print(f"    Injection attempts: {num_attempts}")
    print()

    # SQL injection payloads with actual patterns for detection
    sql_payloads = [
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users WHERE '1'='1",
        "1; DELETE FROM accounts WHERE '1'='1",
        "admin'--",
        "' OR 1=1#",
        "'; INSERT INTO logs VALUES('hacked'); --",
        "' UNION SELECT username, password FROM users --",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
        "'; EXEC xp_cmdshell('dir'); --",
    ]

    # Generate SQL injection traffic pattern
    events = []
    for _ in range(num_attempts):
        payload = random.choice(sql_payloads)
        events.append(
            {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(40000, 65535),
                "destination_port": random.choice([80, 443, 8080]),
                "protocol": random.choice(["http", "https"]),
                "packet_size": len(payload) + random.randint(100, 300),
                "flags": ["PSH", "ACK"],  # HTTP data transfer
                "payload": payload,  # Include actual payload for detection
            }
        )

    print(f"[*] Sending {len(events)} SQL injection attempt packets to API...")
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

    success, data = await simulate_sql_injection(num_attempts=50)

    if success:
        print("\n[+] SQL injection attack simulation completed successfully")
    else:
        print("\n[-] SQL injection attack simulation failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
