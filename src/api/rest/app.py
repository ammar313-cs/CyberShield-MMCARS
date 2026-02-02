"""
FastAPI Application
Main API gateway for CyberShield.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from src.api.rest.v1.router import api_router
from src.api.rest.middleware.traffic_interceptor import TrafficInterceptorMiddleware
from src.api.rest.middleware.rate_limiter import RateLimiterMiddleware
from src.api.rest.middleware.auth import APIKeyMiddleware
from src.infrastructure.persistence.redis_client import init_redis, close_redis
from src.agents.coordinator.orchestrator import AgentOrchestrator

logger = structlog.get_logger(__name__)

# Global orchestrator instance
orchestrator: AgentOrchestrator = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager."""
    global orchestrator

    logger.info("starting_cybershield_api")

    # Initialize Redis
    try:
        await init_redis()
        logger.info("redis_connected")
    except Exception as e:
        logger.warning("redis_connection_failed", error=str(e))

    # Initialize Agent Orchestrator
    orchestrator = AgentOrchestrator(use_redis=True)
    await orchestrator.initialize()
    logger.info("orchestrator_initialized")

    # Store orchestrator in app state
    app.state.orchestrator = orchestrator

    yield

    # Shutdown
    logger.info("shutting_down_cybershield_api")

    if orchestrator:
        await orchestrator.shutdown()

    await close_redis()
    logger.info("cybershield_api_shutdown")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="CyberShield API",
        description="Multi-Model Cyber Attack Response System",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom middleware (order: last added = first to execute)
    # Execution order: Auth -> Rate Limiter -> Traffic Interceptor -> Handler
    app.add_middleware(TrafficInterceptorMiddleware)  # Runs 3rd: logs requests
    app.add_middleware(RateLimiterMiddleware)  # Runs 2nd: rate limiting
    app.add_middleware(
        APIKeyMiddleware,
        exclude_paths=["/api/docs", "/api/redoc", "/api/openapi.json", "/api/v1/health"],  # Allow docs and health check
    )  # Runs 1st: authentication

    # Include API routes
    app.include_router(api_router, prefix="/api/v1")

    # Root endpoint
    @app.get("/", tags=["Root"])
    async def root():
        """Root endpoint."""
        return {
            "name": "CyberShield API",
            "version": "0.1.0",
            "status": "running",
            "docs": "/api/docs",
        }

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.error(
            "unhandled_exception",
            path=request.url.path,
            error=str(exc),
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return app


# Create application instance
app = create_app()


def get_orchestrator() -> AgentOrchestrator:
    """Get the global orchestrator instance."""
    global orchestrator
    return orchestrator
