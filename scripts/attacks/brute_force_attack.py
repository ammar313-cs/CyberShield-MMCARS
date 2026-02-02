#!/usr/bin/env python3
"""
Brute Force Attack Simulation
Simulates a brute force authentication attack pattern.
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
║           BRUTE FORCE ATTACK SIMULATION                        ║
║         Password Guessing / Credential Stuffing                ║
╚═══════════════════════════════════════════════════════════════╝
    """
    )


async def simulate_brute_force(
    attacker_ip: str = None,
    target_ip: str = "10.0.0.1",
    target_service: str = "ssh",  # "ssh", "http", "ftp"
    num_attempts: int = 500,
):
    """
    Simulate Brute Force attack.

    Characteristics:
    - Single source IP
    - Same destination port (service)
    - High frequency of connection attempts
    - Small packet sizes (authentication attempts)
    - Typically targets SSH (22), HTTP (80/443), FTP (21), RDP (3389)
    """
    if attacker_ip is None:
        attacker_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"

    service_ports = {
        "ssh": 22,
        "http": 80,
        "https": 443,
        "ftp": 21,
        "rdp": 3389,
        "smtp": 25,
        "mysql": 3306,
    }

    target_port = service_ports.get(target_service, 22)

    print(f"\n[*] Simulating Brute Force Attack")
    print(f"    Target Service: {target_service.upper()} (port {target_port})")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Target: {target_ip}:{target_port}")
    print(f"    Login attempts: {num_attempts}")
    print()

    # Generate brute force traffic pattern
    events = []
    for _ in range(num_attempts):
        events.append(
            {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(40000, 65535),
                "destination_port": target_port,
                "protocol": "tcp",
                "packet_size": random.randint(100, 500),  # Auth packets vary
                "flags": ["SYN", "PSH", "ACK"],  # Connection + data
            }
        )

    print(f"[*] Sending {len(events)} authentication attempt packets to API...")
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
                        print(f"      Severity: {analysis.get('severity', 'unknown')}")
                        response = result.get("response_plan", {})
                        if response:
                            print(
                                f"      Primary Action: {response.get('primary_action', {}).get('action_type', 'N/A')}"
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

    success, data = await simulate_brute_force(target_service="ssh", num_attempts=200)

    if success:
        print("\n[+] Brute force attack simulation completed successfully")
    else:
        print("\n[-] Brute force attack simulation failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
