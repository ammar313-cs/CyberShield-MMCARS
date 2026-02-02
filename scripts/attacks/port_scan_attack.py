#!/usr/bin/env python3
"""
Port Scan Attack Simulation
Simulates a port scanning/reconnaissance attack pattern.
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
║             PORT SCAN ATTACK SIMULATION                        ║
║          Network Reconnaissance / Service Discovery            ║
╚═══════════════════════════════════════════════════════════════╝
    """
    )


async def simulate_port_scan(
    attacker_ip: str = None,
    target_ip: str = "10.0.0.1",
    scan_type: str = "full",  # "full", "common", "stealth"
):
    """
    Simulate Port Scan attack.

    Characteristics:
    - Single source IP
    - Sequential or random port probing
    - Small packets (SYN probes)
    - Many different destination ports
    """
    if attacker_ip is None:
        attacker_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"

    # Define port ranges based on scan type
    if scan_type == "full":
        ports = list(range(1, 1025))  # First 1024 ports
    elif scan_type == "common":
        ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1723,
            3306,
            3389,
            5432,
            5900,
            8080,
            8443,
        ]
    else:  # stealth
        ports = random.sample(range(1, 65535), 100)

    print(f"\n[*] Simulating Port Scan Attack")
    print(f"    Scan Type: {scan_type}")
    print(f"    Attacker IP: {attacker_ip}")
    print(f"    Target: {target_ip}")
    print(f"    Ports to scan: {len(ports)}")
    print()

    # Generate port scan packets
    events = []
    for port in ports:
        events.append(
            {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(40000, 65535),
                "destination_port": port,
                "protocol": "tcp",
                "packet_size": 64,
                "flags": ["SYN"],  # SYN scan (most common)
            }
        )

    print(f"[*] Sending {len(events)} port probe packets to API...")
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
                        print(f"      Indicators: {', '.join(analysis.get('indicators', [])[:3])}")
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

    success, data = await simulate_port_scan(scan_type="common")

    if success:
        print("\n[+] Port scan attack simulation completed successfully")
    else:
        print("\n[-] Port scan attack simulation failed")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
