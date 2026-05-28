"""Application configuration via Pydantic Settings."""

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All configuration loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Paths
    env_file: Path = Field(default=Path(".env"), alias="ENV_FILE")
    descriptions_path: Path = Field(default=Path("rotate_keys.yaml"), alias="DESCRIPTIONS_PATH")
    data_dir: Path = Field(default=Path("/app/data"), alias="DATA_DIR")

    # Auth
    admin_password: str = Field(default="", alias="ADMIN_PASSWORD")
    reset_key: str = Field(default="", alias="RESET_KEY")
    secret_key: str = Field(default="change-me-in-production", alias="SECRET_KEY")

    # Bitwarden
    bw_session: str = Field(default="", alias="BW_SESSION")

    # Scanning
    scan_interval_minutes: int = Field(default=360, alias="SCAN_INTERVAL_MINUTES")
    cache_max_age_hours: float = Field(default=4.0, alias="CACHE_MAX_AGE_HOURS")
    scan_timeout_minutes: int = Field(default=30, alias="SCAN_TIMEOUT_MINUTES")

    # Auto-rotation (0 = disabled)
    auto_rotate_interval_hours: float = Field(default=0.0, alias="AUTO_ROTATE_INTERVAL_HOURS")

    # Notifications
    webhook_url: str = Field(default="", alias="WEBHOOK_URL")
    webhook_type: str = Field(default="generic", alias="WEBHOOK_TYPE")  # generic, discord, slack, gotify

    # Docker
    docker_socket: Path = Field(default=Path("/var/run/docker.sock"), alias="DOCKER_SOCKET")


settings = Settings()
