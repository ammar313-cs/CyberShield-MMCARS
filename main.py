"""
CyberShield - Multi-Model Cyber Attack Response System
Main entry point for the application.
"""

import asyncio
import os
import sys
from pathlib import Path

import uvicorn
import structlog
from dotenv import load_dotenv

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables
load_dotenv(".env.local")

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


def main():
    """Main entry point."""
    logger.info(
        "starting_cybershield",
        version="0.1.0",
        environment=os.getenv("APP_ENV", "development"),
    )

    # Get configuration from environment
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", 8000))
    workers = int(os.getenv("API_WORKERS", 1))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    log_level = os.getenv("LOG_LEVEL", "info").lower()

    logger.info(
        "configuration",
        host=host,
        port=port,
        workers=workers,
        debug=debug,
        log_level=log_level,
    )

    # Run the API server
    uvicorn.run(
        "src.api.rest.app:app",
        host=host,
        port=port,
        workers=workers if not debug else 1,
        reload=debug,
        log_level=log_level,
        access_log=True,
    )


async def run_services():
    """Run all services concurrently."""
    from src.api.rest.app import create_app
    from src.dashboard.backend.dashboard_service import DashboardService

    logger.info("starting_all_services")

    # Create services
    api_app = create_app()
    dashboard = DashboardService()

    # Get configuration
    api_host = os.getenv("API_HOST", "0.0.0.0")
    api_port = int(os.getenv("API_PORT", 8000))
    dashboard_port = int(os.getenv("DASHBOARD_PORT", 8080))

    # Configure servers
    api_config = uvicorn.Config(
        api_app,
        host=api_host,
        port=api_port,
        log_level="info",
    )
    api_server = uvicorn.Server(api_config)

    dashboard_config = uvicorn.Config(
        dashboard.app,
        host=api_host,
        port=dashboard_port,
        log_level="info",
    )
    dashboard_server = uvicorn.Server(dashboard_config)

    # Run both servers
    await asyncio.gather(
        api_server.serve(),
        dashboard_server.serve(),
    )


def run_all():
    """Run all services (API + Dashboard)."""
    logger.info("starting_cybershield_full_stack")
    asyncio.run(run_services())


def run_api():
    """Run only the API server."""
    main()


def run_dashboard():
    """Run only the dashboard server."""
    from src.dashboard.backend.dashboard_service import main as dashboard_main
    asyncio.run(dashboard_main())


def run_proxy():
    """Run the reverse proxy gateway."""
    from src.proxy.server import run_proxy_server
    from src.proxy.config import ProxyConfig

    logger.info("starting_cybershield_proxy_gateway")

    # Load proxy configuration from environment
    config = ProxyConfig.from_env()

    # Get proxy settings
    host = os.getenv("PROXY_HOST", "0.0.0.0")
    port = int(os.getenv("PROXY_PORT", 8080))

    run_proxy_server(
        host=host,
        port=port,
        config=config,
        with_orchestrator=True,
    )


async def run_full_stack():
    """Run API, Dashboard, and Proxy together."""
    from src.api.rest.app import create_app
    from src.dashboard.backend.dashboard_service import DashboardService
    from src.proxy.gateway import create_proxy_app
    from src.proxy.config import ProxyConfig, UpstreamServer

    logger.info("starting_cybershield_full_stack_with_proxy")

    # Create services
    api_app = create_app()
    dashboard = DashboardService()

    # Create proxy with API as upstream
    proxy_config = ProxyConfig.from_env()
    if not proxy_config.upstream_servers:
        proxy_config.upstream_servers.append(
            UpstreamServer(
                host="localhost",
                port=int(os.getenv("API_PORT", 8000)),
                health_check_path="/api/v1/health",
            )
        )
    proxy_app = create_proxy_app(config=proxy_config)

    # Get ports
    api_host = os.getenv("API_HOST", "0.0.0.0")
    api_port = int(os.getenv("API_PORT", 8000))
    dashboard_port = int(os.getenv("DASHBOARD_PORT", 8081))
    proxy_port = int(os.getenv("PROXY_PORT", 8080))

    # Configure servers
    api_config = uvicorn.Config(api_app, host=api_host, port=api_port, log_level="info")
    api_server = uvicorn.Server(api_config)

    dashboard_config = uvicorn.Config(dashboard.app, host=api_host, port=dashboard_port, log_level="info")
    dashboard_server = uvicorn.Server(dashboard_config)

    proxy_config_uv = uvicorn.Config(proxy_app, host=api_host, port=proxy_port, log_level="info")
    proxy_server = uvicorn.Server(proxy_config_uv)

    logger.info(
        "services_configured",
        api_port=api_port,
        dashboard_port=dashboard_port,
        proxy_port=proxy_port,
    )

    # Run all servers
    await asyncio.gather(
        api_server.serve(),
        dashboard_server.serve(),
        proxy_server.serve(),
    )


def run_full():
    """Run full stack with proxy."""
    asyncio.run(run_full_stack())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="CyberShield - Multi-Model Cyber Attack Response System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --mode api          # Run API server only
  python main.py --mode dashboard    # Run dashboard only
  python main.py --mode proxy        # Run reverse proxy gateway only
  python main.py --mode all          # Run API + dashboard
  python main.py --mode full         # Run API + dashboard + proxy
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["api", "dashboard", "proxy", "all", "full"],
        default="api",
        help="Service mode to run (default: api)",
    )

    args = parser.parse_args()

    if args.mode == "api":
        run_api()
    elif args.mode == "dashboard":
        run_dashboard()
    elif args.mode == "proxy":
        run_proxy()
    elif args.mode == "all":
        run_all()
    elif args.mode == "full":
        run_full()
