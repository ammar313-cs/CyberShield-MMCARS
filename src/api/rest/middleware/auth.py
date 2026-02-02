"""
API Key Authentication Middleware
Validates API keys on all incoming requests.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import structlog

from src.api.rest.security import verify_api_key, extract_api_key_from_headers

logger = structlog.get_logger(__name__)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware that validates API keys on all requests.

    Accepts API keys via:
    - X-API-Key header
    - Authorization: Bearer <key> header

    Returns 401 Unauthorized for missing or invalid keys.
    """

    def __init__(self, app, exclude_paths: list[str] = None):
        """
        Initialize the middleware.

        Args:
            app: The ASGI application
            exclude_paths: List of paths to exclude from auth (e.g., ["/docs"])
        """
        super().__init__(app)
        self.exclude_paths = exclude_paths or []
        self._request_count = 0
        self._unauthorized_count = 0

    async def dispatch(self, request: Request, call_next):
        """
        Process the request and validate API key.

        Args:
            request: The incoming request
            call_next: The next middleware/handler

        Returns:
            Response from next handler or 401 error
        """
        self._request_count += 1

        # Check if path is excluded from auth
        path = request.url.path
        if self._is_excluded(path):
            return await call_next(request)

        # Extract API key from headers
        api_key = extract_api_key_from_headers(dict(request.headers))

        # Get client IP for logging
        client_ip = self._get_client_ip(request)

        # Validate API key
        if not api_key:
            self._unauthorized_count += 1
            logger.warning(
                "auth_failed_missing_key",
                client_ip=client_ip,
                path=path,
                method=request.method,
            )
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "API key required",
                    "error": "missing_api_key",
                    "hint": "Include X-API-Key header or Authorization: Bearer <key>",
                },
            )

        if not verify_api_key(api_key):
            self._unauthorized_count += 1
            logger.warning(
                "auth_failed_invalid_key",
                client_ip=client_ip,
                path=path,
                method=request.method,
                key_prefix=api_key[:8] + "..." if len(api_key) > 8 else "***",
            )
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "Invalid API key",
                    "error": "invalid_api_key",
                },
            )

        # Key is valid - continue to next handler
        logger.debug(
            "auth_success",
            client_ip=client_ip,
            path=path,
            method=request.method,
        )

        return await call_next(request)

    def _is_excluded(self, path: str) -> bool:
        """Check if path is excluded from authentication."""
        for excluded in self.exclude_paths:
            if path.startswith(excluded):
                return True
        return False

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, handling proxies."""
        # Check for forwarded headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fall back to direct client
        if request.client:
            return request.client.host

        return "unknown"

    def get_stats(self) -> dict:
        """Get middleware statistics."""
        return {
            "total_requests": self._request_count,
            "unauthorized_requests": self._unauthorized_count,
            "excluded_paths": self.exclude_paths,
            "success_rate": (
                (self._request_count - self._unauthorized_count) / self._request_count
                if self._request_count > 0
                else 1.0
            ),
        }
