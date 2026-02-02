"""
Proxy Server Entry Point

Standalone server for running CyberShield as a reverse proxy gateway.
"""

import asyncio
import os
import sys
import signal
from typing import Optional
import structlog
import uvicorn

from src.proxy.config import ProxyConfig, UpstreamServer, InspectionMode, LoadBalanceStrategy
from src.proxy.gateway import create_proxy_app, ReverseProxyGateway
from src.agents.coordinator.orchestrator import AgentOrchestrator

logger = structlog.get_logger(__name__)


def create_default_config() -> ProxyConfig:
    """Create default proxy configuration from environment."""
    config = ProxyConfig.from_env()

    # Add default upstream if none configured
    if not config.upstream_servers:
        # Default: forward to local API server
        default_host = os.getenv("PROXY_DEFAULT_UPSTREAM_HOST", "localhost")
        default_port = int(os.getenv("PROXY_DEFAULT_UPSTREAM_PORT", "8000"))

        config.upstream_servers.append(
            UpstreamServer(
                host=default_host,
                port=default_port,
                weight=1,
                health_check_path="/api/v1/health",
            )
        )

    return config


def run_proxy_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    config: Optional[ProxyConfig] = None,
    with_orchestrator: bool = True,
    reload: bool = False,
    workers: int = 1,
    log_level: str = "info",
) -> None:
    """
    Run the reverse proxy server.

    Args:
        host: Host to bind to
        port: Port to listen on
        config: Proxy configuration
        with_orchestrator: Whether to include the agent orchestrator
        reload: Enable auto-reload for development
        workers: Number of worker processes
        log_level: Logging level
    """
    if config is None:
        config = create_default_config()

    # Override host/port from arguments
    config.listen_host = host
    config.listen_port = port

    # Validate
    errors = config.validate()
    if errors:
        logger.error("configuration_invalid", errors=errors)
        print(f"Configuration errors: {errors}")
        sys.exit(1)

    print_banner(config)

    # Create orchestrator if requested
    orchestrator = None
    if with_orchestrator:
        orchestrator = AgentOrchestrator(use_redis=True)

    # Create the FastAPI app
    app = create_proxy_app(config=config, orchestrator=orchestrator)

    # Run with uvicorn
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        log_level=log_level,
        access_log=config.log_requests,
    )


def print_banner(config: ProxyConfig) -> None:
    """Print startup banner."""
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ║
║    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ║
║    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ║
║    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ║
║    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║██║███████╗███████╗║
║     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝║
║                                                                               ║
║                    REVERSE PROXY GATEWAY MODE                                 ║
║                 Multi-Model Cyber Attack Response System                      ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
""")

    print(f"""
┌─────────────────────────────────────────────────────────────────────────────┐
│  Configuration                                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  Listen Address:    {config.listen_host}:{config.listen_port:<43}│
│  Inspection Mode:   {config.inspection_mode.value:<47}│
│  Threat Threshold:  {config.threat_threshold:<47}│
│  Load Balancing:    {config.load_balance_strategy.value:<47}│
│  Rate Limit:        {config.rate_limit_requests} req/{config.rate_limit_window}s{' ' * 36}│
├─────────────────────────────────────────────────────────────────────────────┤
│  Upstream Servers                                                            │
├─────────────────────────────────────────────────────────────────────────────┤""")

    for i, server in enumerate(config.upstream_servers):
        print(f"│  [{i+1}] {server.url:<65}│")

    print("""├─────────────────────────────────────────────────────────────────────────────┤
│  Features                                                                    │
├─────────────────────────────────────────────────────────────────────────────┤""")
    print(f"│  • ML Detection:       {'Enabled' if config.enable_ml_detection else 'Disabled':<50}│")
    print(f"│  • Pattern Matching:   {'Enabled' if config.enable_pattern_matching else 'Disabled':<50}│")
    print(f"│  • Rate Limiting:      {'Enabled' if config.enable_rate_limiting else 'Disabled':<50}│")
    print(f"│  • WebSocket Proxy:    {'Enabled' if config.enable_websocket else 'Disabled':<50}│")
    print(f"│  • Circuit Breaker:    {'Enabled' if config.enable_circuit_breaker else 'Disabled':<50}│")
    print("""└─────────────────────────────────────────────────────────────────────────────┘

  Management Endpoints:
    • GET  /_proxy/status          - Gateway status and statistics
    • GET  /_proxy/health          - Health check
    • GET  /_proxy/inspector/stats - Inspector statistics
    • GET  /_proxy/forwarder/stats - Forwarder statistics
    • POST /_proxy/block/{ip}      - Block an IP address
    • POST /_proxy/unblock/{ip}    - Unblock an IP address

  Starting proxy server...
""")


def main():
    """Main entry point for proxy server."""
    import argparse

    parser = argparse.ArgumentParser(
        description="CyberShield Reverse Proxy Gateway",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run proxy with default settings
  python -m src.proxy.server

  # Run proxy on custom port
  python -m src.proxy.server --port 9000

  # Run proxy with specific upstream
  python -m src.proxy.server --upstream localhost:8000

  # Run in passive mode (log only, no blocking)
  python -m src.proxy.server --mode passive

  # Run with multiple upstreams
  python -m src.proxy.server --upstream server1:8000 --upstream server2:8000
        """,
    )

    parser.add_argument(
        "--host",
        default=os.getenv("PROXY_HOST", "0.0.0.0"),
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PROXY_PORT", "8080")),
        help="Port to listen on (default: 8080)",
    )
    parser.add_argument(
        "--upstream",
        action="append",
        dest="upstreams",
        help="Upstream server (format: host:port or host:port:weight)",
    )
    parser.add_argument(
        "--mode",
        choices=["passive", "active", "strict", "learning"],
        default=os.getenv("PROXY_INSPECTION_MODE", "active"),
        help="Inspection mode (default: active)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=float(os.getenv("PROXY_THREAT_THRESHOLD", "0.7")),
        help="Threat confidence threshold (0.0-1.0, default: 0.7)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=int(os.getenv("PROXY_RATE_LIMIT", "100")),
        help="Rate limit (requests per window, default: 100)",
    )
    parser.add_argument(
        "--rate-window",
        type=int,
        default=int(os.getenv("PROXY_RATE_WINDOW", "60")),
        help="Rate limit window in seconds (default: 60)",
    )
    parser.add_argument(
        "--no-orchestrator",
        action="store_true",
        help="Disable agent orchestrator integration",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Log level (default: info)",
    )

    args = parser.parse_args()

    # Build configuration
    config = ProxyConfig(
        listen_host=args.host,
        listen_port=args.port,
        inspection_mode=InspectionMode(args.mode),
        threat_threshold=args.threshold,
        rate_limit_requests=args.rate_limit,
        rate_limit_window=args.rate_window,
    )

    # Add upstream servers
    if args.upstreams:
        for upstream in args.upstreams:
            parts = upstream.split(":")
            if len(parts) >= 2:
                host = parts[0]
                port = int(parts[1])
                weight = int(parts[2]) if len(parts) > 2 else 1
                config.upstream_servers.append(
                    UpstreamServer(host=host, port=port, weight=weight)
                )
    else:
        # Default upstream
        config.upstream_servers.append(
            UpstreamServer(
                host="localhost",
                port=8000,
                health_check_path="/api/v1/health",
            )
        )

    # Run server
    run_proxy_server(
        host=args.host,
        port=args.port,
        config=config,
        with_orchestrator=not args.no_orchestrator,
        reload=args.reload,
        workers=args.workers,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
