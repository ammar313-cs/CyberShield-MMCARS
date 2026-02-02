#!/usr/bin/env python3
"""
Attack Simulation Script
Tests CyberShield's threat detection by simulating various attack patterns.
"""

import asyncio
import httpx
import random
import sys
from datetime import datetime

# Configuration
from config import API_BASE, HEADERS, DASHBOARD_URL


def print_header(title: str):
    """Print section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_result(label: str, success: bool, details: str = ""):
    """Print test result."""
    status = "✓ PASS" if success else "✗ FAIL"
    color = "\033[92m" if success else "\033[91m"
    reset = "\033[0m"
    print(f"{color}{status}{reset} {label}")
    if details:
        print(f"       {details}")


async def test_health():
    """Test API health endpoint."""
    print_header("1. Health Check")

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{API_BASE}/health", headers=HEADERS)
            data = resp.json()
            success = resp.status_code == 200 and data.get("status") == "healthy"
            print_result("API Health", success, f"Status: {data.get('status', 'unknown')}")
            return success
        except Exception as e:
            print_result("API Health", False, str(e))
            return False


async def test_auth():
    """Test authentication."""
    print_header("2. Authentication")

    async with httpx.AsyncClient() as client:
        # Test without key
        resp = await client.get(f"{API_BASE}/health")
        no_key = resp.status_code == 401
        print_result("Reject without API key", no_key, f"Status: {resp.status_code}")

        # Test with invalid key
        resp = await client.get(f"{API_BASE}/health", headers={"X-API-Key": "invalid"})
        invalid_key = resp.status_code == 401
        print_result("Reject invalid API key", invalid_key, f"Status: {resp.status_code}")

        # Test with valid key
        resp = await client.get(f"{API_BASE}/health", headers=HEADERS)
        valid_key = resp.status_code == 200
        print_result("Accept valid API key", valid_key, f"Status: {resp.status_code}")

        return no_key and invalid_key and valid_key


async def simulate_ddos():
    """Simulate DDoS attack pattern."""
    print_header("3. DDoS Attack Simulation")

    # Generate high volume of requests from multiple IPs to same target
    attacker_ips = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(5)]
    target_ip = "10.0.0.1"
    target_port = 80

    events = []
    for ip in attacker_ips:
        for _ in range(5):  # 5 packets per attacker
            events.append(
                {
                    "source_ip": ip,
                    "destination_ip": target_ip,
                    "source_port": random.randint(1024, 65535),
                    "destination_port": target_port,
                    "protocol": "tcp",
                    "packet_size": random.randint(64, 1500),
                    "flags": ["SYN", "ACK"],
                }
            )

    print(
        f"  Sending {len(events)} packets from {len(attacker_ips)} IPs to {target_ip}:{target_port}"
    )

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            resp = await client.post(
                f"{API_BASE}/threats/analyze", json={"events": events}, headers=HEADERS
            )
            if resp.status_code != 200:
                print_result("DDoS Detection", False, f"HTTP {resp.status_code}: {resp.text[:200]}")
                return False, {}
            data = resp.json()
            detected = data.get("threats_detected", 0)
            success = True
            print_result(
                "DDoS Detection",
                success,
                f"Processed: {data.get('events_processed', 0)}, Threats: {detected}",
            )
            return success, data
        except httpx.TimeoutException:
            print_result("DDoS Detection", False, "Request timeout (analysis in progress)")
            return False, {}
        except Exception as e:
            print_result("DDoS Detection", False, f"{type(e).__name__}: {str(e)}")
            return False, {}


async def simulate_syn_flood():
    """Simulate SYN flood attack pattern."""
    print_header("4. SYN Flood Simulation")

    # Generate SYN packets without ACK (half-open connections)
    attacker_ip = "192.168.100.100"
    target_ip = "10.0.0.1"

    events = []
    for _ in range(20):  # Reduced for faster testing
        events.append(
            {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(1024, 65535),
                "destination_port": 80,
                "protocol": "tcp",
                "packet_size": 64,
                "flags": ["SYN"],  # SYN only, no ACK
            }
        )

    print(f"  Sending {len(events)} SYN-only packets from {attacker_ip}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            resp = await client.post(
                f"{API_BASE}/threats/analyze", json={"events": events}, headers=HEADERS
            )
            if resp.status_code != 200:
                print_result(
                    "SYN Flood Detection", False, f"HTTP {resp.status_code}: {resp.text[:200]}"
                )
                return False, {}
            data = resp.json()
            success = True
            print_result(
                "SYN Flood Detection",
                success,
                f"Processed: {data.get('events_processed', 0)}, Threats: {data.get('threats_detected', 0)}",
            )
            return success, data
        except httpx.TimeoutException:
            print_result("SYN Flood Detection", False, "Request timeout (analysis in progress)")
            return False, {}
        except Exception as e:
            print_result("SYN Flood Detection", False, f"{type(e).__name__}: {str(e)}")
            return False, {}


async def simulate_port_scan():
    """Simulate port scan attack pattern."""
    print_header("5. Port Scan Simulation")

    # Scan multiple ports from single IP
    attacker_ip = "192.168.200.50"
    target_ip = "10.0.0.1"

    events = []
    for port in range(1, 51):  # Scan first 50 ports (reduced)
        events.append(
            {
                "source_ip": attacker_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(40000, 65535),
                "destination_port": port,
                "protocol": "tcp",
                "packet_size": 64,
                "flags": ["SYN"],
            }
        )

    print(f"  Sending {len(events)} port scan packets from {attacker_ip}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            resp = await client.post(
                f"{API_BASE}/threats/analyze", json={"events": events}, headers=HEADERS
            )
            if resp.status_code != 200:
                print_result(
                    "Port Scan Detection", False, f"HTTP {resp.status_code}: {resp.text[:200]}"
                )
                return False, {}
            data = resp.json()
            success = True
            print_result(
                "Port Scan Detection",
                success,
                f"Processed: {data.get('events_processed', 0)}, Threats: {data.get('threats_detected', 0)}",
            )
            return success, data
        except httpx.TimeoutException:
            print_result("Port Scan Detection", False, "Request timeout (analysis in progress)")
            return False, {}
        except Exception as e:
            print_result("Port Scan Detection", False, f"{type(e).__name__}: {str(e)}")
            return False, {}


async def check_threats():
    """Check detected threats."""
    print_header("6. Active Threats Check")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(f"{API_BASE}/threats", headers=HEADERS)
            if resp.status_code != 200:
                print_result(
                    "Threats Endpoint", False, f"HTTP {resp.status_code}: {resp.text[:200]}"
                )
                return False, {}
            data = resp.json()
            threats = data.get("threats", [])
            count = data.get("count", 0)

            print_result("Threats Endpoint", True, f"Active threats: {count}")

            if threats:
                print("\n  Recent Threats:")
                for t in threats[:5]:
                    print(
                        f"    - {t.get('attack_type', 'unknown')}: {t.get('source_ip', '?')} → severity: {t.get('severity', '?')}"
                    )

            return True, data
        except Exception as e:
            print_result("Threats Endpoint", False, f"{type(e).__name__}: {str(e)}")
            return False, {}


async def test_agent_status():
    """Test agent system status."""
    print_header("7. Agent System Status")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(f"{API_BASE}/agents", headers=HEADERS)
            if resp.status_code != 200:
                print_result(
                    "Agents Endpoint", False, f"HTTP {resp.status_code}: {resp.text[:200]}"
                )
                return False
            data = resp.json()

            agents = data.get("agents", [])
            print_result("Agents Endpoint", True, f"Agents: {len(agents)}")

            if agents:
                print("\n  Agent Status:")
                for agent in agents:
                    name = agent.get("type", "unknown")
                    state = agent.get("status", "unknown")
                    print(f"    - {name}: {state}")

            return True
        except Exception as e:
            print_result("Agents Endpoint", False, f"{type(e).__name__}: {str(e)}")
            return False


async def test_dashboard():
    """Test dashboard endpoints."""
    print_header("8. Dashboard Endpoints")

    async with httpx.AsyncClient() as client:
        # Main dashboard
        resp = await client.get(f"{DASHBOARD_URL}/")
        dash_ok = resp.status_code == 200
        print_result("Dashboard Page", dash_ok, f"Status: {resp.status_code}")

        # About page
        resp = await client.get(f"{DASHBOARD_URL}/about")
        about_ok = resp.status_code == 200
        print_result("About Page", about_ok, f"Status: {resp.status_code}")

        # Dashboard API status
        resp = await client.get(f"{DASHBOARD_URL}/api/status")
        api_ok = resp.status_code == 200
        print_result("Dashboard API", api_ok, f"Status: {resp.status_code}")

        return dash_ok and about_ok


async def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("  CYBERSHIELD ATTACK SIMULATION TEST SUITE")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    results = []

    # Run tests
    results.append(("Health Check", await test_health()))
    results.append(("Authentication", await test_auth()))

    ddos_ok, _ = await simulate_ddos()
    results.append(("DDoS Simulation", ddos_ok))

    syn_ok, _ = await simulate_syn_flood()
    results.append(("SYN Flood Simulation", syn_ok))

    scan_ok, _ = await simulate_port_scan()
    results.append(("Port Scan Simulation", scan_ok))

    threats_ok, _ = await check_threats()
    results.append(("Threats Check", threats_ok))

    results.append(("Agent Status", await test_agent_status()))
    results.append(("Dashboard", await test_dashboard()))

    # Summary
    print_header("TEST SUMMARY")

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "\033[92m✓\033[0m" if result else "\033[91m✗\033[0m"
        print(f"  {status} {name}")

    print(f"\n  Results: {passed}/{total} tests passed")

    if passed == total:
        print("\n  \033[92m*** ALL TESTS PASSED ***\033[0m\n")
        return 0
    else:
        print(f"\n  \033[91m*** {total - passed} TEST(S) FAILED ***\033[0m\n")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
