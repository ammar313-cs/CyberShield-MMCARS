"""
Centralized configuration for attack simulation scripts.
Loads settings from environment variables.
"""

import os
from pathlib import Path

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    # Find .env file in project root (parent of scripts/)
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

# API Configuration
API_BASE = os.getenv("API_BASE", "http://localhost:8000/api/v1")
API_KEY = os.getenv("API_KEY", "cs_t45QILiSOwmXUa2MZzofhKkPXkT58hYgCDYaF-EefJg")
HEADERS = {"X-API-Key": API_KEY}

# Dashboard Configuration
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8080")
