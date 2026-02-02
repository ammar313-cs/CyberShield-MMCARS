"""REST API - FastAPI application and routes."""

from src.api.rest.app import app, create_app, get_orchestrator
from src.api.rest.security import verify_api_key, generate_api_key
from src.api.rest.v1 import api_router
from src.api.rest.middleware import (
    APIKeyMiddleware,
    RateLimiterMiddleware,
    TrafficInterceptorMiddleware,
)

__all__ = [
    "app",
    "create_app",
    "get_orchestrator",
    "verify_api_key",
    "generate_api_key",
    "api_router",
    "APIKeyMiddleware",
    "RateLimiterMiddleware",
    "TrafficInterceptorMiddleware",
]
