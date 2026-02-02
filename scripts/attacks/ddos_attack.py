#!/usr/bin/env python3
"""
DDoS Attack Simulation
Simulates a Distributed Denial of Service attack pattern.
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
║             DDoS ATTACK SIMULATION                             ║
║        Distributed Denial of Service Attack                    ║
╚═══════════════════════════════════════════════════════════════╝
    """
    )


async def simulate_ddos(
    num_attackers: int = 50,
    packets_per_attacker: int = 20,
    target_ip: str = "10.0.0.1",
    target_port: int = 80,
):
    """
    Simulate DDoS attack with multiple source IPs flooding a target.

    Characteristics:
    - High volume of traffic from many different IPs
    - Same target IP and port
    - Various packet sizes
    - Mix of TCP flags
    """
    print(f"\n[*] Simulating DDoS Attack")
    print(f"    Attackers: {num_attackers}")
    print(f"    Packets per attacker: {packets_per_attacker}")
    print(f"    Target: {target_ip}:{target_port}")
    print(f"    Total packets: {num_attackers * packets_per_attacker}")
    print()

    # Generate attacker IPs from different subnets (botnet simulation)
    attacker_ips = []
    for _ in range(num_attackers):
        # Use /16 subnets (2 octets) so we can add 2 more random octets
        subnet = random.choice(["192.168", "10.0", "172.16", "203.0", "198.51"])
        ip = f"{subnet}.{random.randint(1,254)}.{random.randint(1,254)}"
        attacker_ips.append(ip)

    # Generate traffic events
    events = []
    for ip in attacker_ips:
        for _ in range(packets_per_attacker):
            events.append(
                {
                    "source_ip": ip,
                    "destination_ip": target_ip,
                    "source_port": random.randint(1024, 65535),
                    "destination_port": target_port,
                    "protocol": random.choice(["tcp", "udp"]),
                    "packet_size": random.randint(64, 1500),
                    "flags": random.choice([["SYN"], ["SYN", "ACK"], ["ACK"], ["PSH", "ACK"]]),
                }
            )

    print(f"[*] Sending {len(events)} packets to API...")
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
                    for result in data["results"][:5]:
                        print(f"    - Threat ID: {result.get('threat_id', 'N/A')[:8]}...")
                        print(
                            f"      Attack Type: {result.get('analysis', {}).get('attack_type', 'unknown')}"
                        )
                        print(
                            f"      Severity: {result.get('analysis', {}).get('severity', 'unknown')}"
                        )
                        print(
                            f"      Response: {result.get('response_plan', {}).get('primary_action', {}).get('action_type', 'N/A')}"
                        )
                        print()

                return True, data
            else:
                print(f"\n[-] FAILED - HTTP {resp.status_code}")
                print(f"    {resp.text[:200]}")
                return False, {}

        except Exception as e:
            print(f"\n[-] ERROR - {type(e).__name__}: {str(e)}")
            return False, {}


async def main():
    print_banner()

    # Run attack simulation
    success, data = await simulate_ddos(
        num_attackers=30,
        packets_per_attacker=10,
    )

    if success:
        print("\n[+] DDoS attack simulation completed successfully")
        print("    Check the dashboard for detected threats and agent actions")
    else:
        print("\n[-] DDoS attack simulation failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
