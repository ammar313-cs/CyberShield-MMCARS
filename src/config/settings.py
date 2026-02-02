"""
CyberShield Settings
Pydantic-based configuration with support for env vars and config files.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Application-level settings."""

    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    name: str = Field(default="CyberShield", alias="APP_NAME")
    env: str = Field(default="development", alias="APP_ENV")
    debug: bool = Field(default=True, alias="DEBUG")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # API settings
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=4, alias="API_WORKERS")


class SecuritySettings(BaseSettings):
    """Security and authentication settings."""

    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    secret_key: str = Field(
        default="change-me-in-production",
        alias="SECRET_KEY",
    )
    allowed_hosts: list[str] = Field(
        default=["localhost", "127.0.0.1"],
        alias="ALLOWED_HOSTS",
    )
    api_keys: list[str] = Field(
        default=[],
        alias="API_KEYS",
    )

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return v

    @field_validator("api_keys", mode="before")
    @classmethod
    def parse_api_keys(cls, v):
        if isinstance(v, str):
            return [k.strip() for k in v.split(",") if k.strip()]
        return v


class RedisSettings(BaseSettings):
    """Redis/LangCache settings."""

    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    # LangCache (production)
    lang_cache_api_key: Optional[str] = Field(default=None, alias="LANG_CACHE_API_KEY")
    cache_id: Optional[str] = Field(default=None, alias="CACHE_ID")
    cache_url: str = Field(
        default="https://aws-us-east-1.langcache.redis.io",
        alias="CACHE_URL",
    )

    # Local Redis (development)
    host: str = Field(default="localhost", alias="REDIS_HOST")
    port: int = Field(default=6379, alias="REDIS_PORT")
    password: Optional[str] = Field(default=None, alias="REDIS_PASSWORD")
    db: int = Field(default=0, alias="REDIS_DB")

    @property
    def is_langcache_configured(self) -> bool:
        """Check if LangCache credentials are available."""
        return bool(self.lang_cache_api_key and self.cache_id)


class MLSettings(BaseSettings):
    """Machine Learning settings."""

    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    model_path: Path = Field(default=Path("src/ml/weights"), alias="ML_MODEL_PATH")
    anomaly_threshold: float = Field(default=0.7, alias="ANOMALY_THRESHOLD")
    pattern_threshold: float = Field(default=0.8, alias="PATTERN_THRESHOLD")
    ensemble_weights: list[float] = Field(
        default=[0.4, 0.3, 0.3],
        alias="ENSEMBLE_WEIGHTS",
    )

    @field_validator("ensemble_weights", mode="before")
    @classmethod
    def parse_weights(cls, v):
        if isinstance(v, str):
            return [float(w.strip()) for w in v.split(",") if w.strip()]
        return v

    @field_validator("model_path", mode="before")
    @classmethod
    def parse_path(cls, v):
        if isinstance(v, str):
            return Path(v)
        return v


class AgentSettings(BaseSettings):
    """AI Agent settings."""

    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    # Claude API
    claude_api_key: Optional[str] = Field(default=None, alias="CLAUDE_API_KEY")
    claude_model: str = Field(default="claude-sonnet-4-20250514", alias="CLAUDE_MODEL")

    # Coordination
    coordination_timeout: int = Field(default=5000, alias="AGENT_COORDINATION_TIMEOUT")
    max_retries: int = Field(default=3, alias="AGENT_MAX_RETRIES")
    response_window: int = Field(default=1000, alias="AGENT_RESPONSE_WINDOW")
    max_concurrent: int = Field(default=10, alias="AGENT_MAX_CONCURRENT")


class ResponseSettings(BaseSettings):
    """Response/Mitigation settings."""

    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    ip_block_duration: int = Field(default=3600, alias="IP_BLOCK_DURATION")
    rate_limit_window: int = Field(default=60, alias="RATE_LIMIT_WINDOW")
    rate_limit_max_requests: int = Field(default=100, alias="RATE_LIMIT_MAX_REQUESTS")
    auto_mitigation_enabled: bool = Field(default=True, alias="AUTO_MITIGATION_ENABLED")


class DashboardSettings(BaseSettings):
    """Dashboard settings."""

    model_config = SettingsConfigDict(
        env_prefix="",
        extra="ignore",
    )

    host: str = Field(default="0.0.0.0", alias="DASHBOARD_HOST")
    port: int = Field(default=8080, alias="DASHBOARD_PORT")
    websocket_heartbeat: int = Field(default=30, alias="WEBSOCKET_HEARTBEAT_INTERVAL")


class Settings(BaseSettings):
    """
    Main settings class that aggregates all config sections.

    Usage:
        from src.config import get_settings

        settings = get_settings()
        print(settings.app.name)
        print(settings.security.api_keys)
    """

    model_config = SettingsConfigDict(
        env_file=".env.local",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Sub-settings
    app: AppSettings = Field(default_factory=AppSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    ml: MLSettings = Field(default_factory=MLSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    response: ResponseSettings = Field(default_factory=ResponseSettings)
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)

    def __init__(self, **data):
        super().__init__(**data)
        # Initialize sub-settings with same env source
        self.app = AppSettings()
        self.security = SecuritySettings()
        self.redis = RedisSettings()
        self.ml = MLSettings()
        self.agent = AgentSettings()
        self.response = ResponseSettings()
        self.dashboard = DashboardSettings()


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.

    Returns:
        Settings: The application settings
    """
    return Settings()


def reload_settings() -> Settings:
    """
    Reload settings (clears cache).

    Returns:
        Settings: Fresh settings instance
    """
    get_settings.cache_clear()
    return get_settings()
