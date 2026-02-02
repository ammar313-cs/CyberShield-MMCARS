"""
API Security Utilities
Handles API key validation and generation for CyberShield.
"""

import os
import secrets
from functools import lru_cache
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


@lru_cache()
def get_api_keys() -> set[str]:
    """
    Load API keys from environment.

    Keys are comma-separated in the API_KEYS environment variable.
    Uses caching to avoid repeated env lookups.

    Returns:
        Set of valid API keys
    """
    keys_str = os.getenv("API_KEYS", "")
    keys = set(k.strip() for k in keys_str.split(",") if k.strip())

    if not keys:
        logger.warning(
            "no_api_keys_configured",
            message="API_KEYS environment variable is empty or not set",
        )

    return keys


def clear_api_keys_cache() -> None:
    """Clear the API keys cache (useful for testing or key rotation)."""
    get_api_keys.cache_clear()


def verify_api_key(key: Optional[str]) -> bool:
    """
    Verify an API key using constant-time comparison.

    Uses secrets.compare_digest to prevent timing attacks.

    Args:
        key: The API key to verify

    Returns:
        True if the key is valid, False otherwise
    """
    if not key:
        return False

    valid_keys = get_api_keys()

    if not valid_keys:
        # No keys configured - deny all requests
        logger.error("api_key_validation_failed", reason="no_keys_configured")
        return False

    # Use constant-time comparison for each key
    is_valid = any(secrets.compare_digest(key, valid) for valid in valid_keys)

    if not is_valid:
        logger.warning(
            "api_key_validation_failed",
            key_prefix=key[:8] + "..." if len(key) > 8 else "***",
        )

    return is_valid


def generate_api_key(prefix: str = "cs") -> str:
    """
    Generate a secure random API key.

    Args:
        prefix: Prefix for the key (default: "cs" for CyberShield)

    Returns:
        A secure random API key in format: {prefix}_{random_token}

    Example:
        >>> generate_api_key()
        'cs_Ab3Kd9Xp2mN...'
    """
    # Generate 32 bytes of random data (256 bits of entropy)
    token = secrets.token_urlsafe(32)
    return f"{prefix}_{token}"


def extract_api_key_from_headers(
    headers: dict,
    x_api_key_header: str = "x-api-key",
    auth_header: str = "authorization",
) -> Optional[str]:
    """
    Extract API key from request headers.

    Supports two formats:
    1. X-API-Key: <key>
    2. Authorization: Bearer <key>

    Args:
        headers: Request headers dict (keys should be lowercase)
        x_api_key_header: Name of the X-API-Key header (lowercase)
        auth_header: Name of the Authorization header (lowercase)

    Returns:
        The extracted API key or None if not found
    """
    # Normalize headers to lowercase keys for consistent lookup
    normalized = {k.lower(): v for k, v in headers.items()}

    # Check X-API-Key header first
    api_key = normalized.get(x_api_key_header)
    if api_key:
        return api_key

    # Check Authorization header
    auth_value = normalized.get(auth_header, "")
    if auth_value.startswith("Bearer "):
        return auth_value[7:]

    return None


# CLI helper for generating keys
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        prefix = sys.argv[2] if len(sys.argv) > 2 else "cs"
        key = generate_api_key(prefix)
        print(f"Generated API Key: {key}")
        print("\nAdd to .env.local:")
        print(f"API_KEYS={key}")
    else:
        print("Usage: python -m src.api.rest.security generate [prefix]")
        print("\nExample:")
        print("  python -m src.api.rest.security generate")
        print("  python -m src.api.rest.security generate myapp")
