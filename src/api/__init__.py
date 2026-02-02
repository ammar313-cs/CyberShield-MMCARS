"""
CyberShield API Layer
REST API and WebSocket interfaces.
"""

from src.api.rest import app, create_app

__all__ = [
    "app",
    "create_app",
]
