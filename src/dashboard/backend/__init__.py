"""Dashboard Backend - WebSocket service and API."""

from src.dashboard.backend.dashboard_service import DashboardService, ConnectionManager

__all__ = [
    "DashboardService",
    "ConnectionManager",
]
