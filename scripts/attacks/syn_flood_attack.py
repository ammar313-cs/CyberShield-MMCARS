#!/usr/bin/env python3
"""
SYN Flood Attack Simulation
Simulates a TCP SYN flood attack pattern.
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
║             SYN FLOOD ATTACK SIMULATION                        ║
║            TCP Half-Open Connection Flood                      ║
╚═══════════════════════════════════════════════════════════════╝
    """
    )


async def simulate_syn_flood(
    attacker_ip: str = None,
    num_packets: int = 500,
    target_ip: str = "10.0.0.1",
    target_port: int = 80,
):
    """
    Simulate SYN Flood attack.

    Characteristics:
    - Single or few source IPs
    - SYN flag only (no ACK - half-open connections)
    - High packet rate
    - Same target port
    - Exhausts server's connection table
    """
    if attacker_ip is None:
        attacker_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"

    print(f"\n[*] Simulating SYN Flood Attack")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Target: {target_ip}:{target_port}")
    print(f"    SYN packets: {num_packets}")
    print()

    # Generate SYN-only packets (no ACK)
    events = []
    for _ in range(num_packets):
        events.append(
            {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(1024, 65535),
                "destination_port": target_port,
                "protocol": "tcp",
                "packet_size": 64,  # SYN packets are typically small
                "flags": ["SYN"],  # SYN only - key characteristic
            }
        )

    print(f"[*] Sending {len(events)} SYN packets to API...")
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
                        print(f"      Summary: {analysis.get('summary', 'N/A')[:100]}...")
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

    success, data = await simulate_syn_flood(num_packets=200)

    if success:
        print("\n[+] SYN Flood attack simulation completed successfully")
        print("    The system should have detected and responded to the attack")
    else:
        print("\n[-] SYN Flood attack simulation failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
