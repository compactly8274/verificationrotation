"""Application configuration via Pydantic Settings."""

import logging
import os
import secrets
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# If .env exists but isn't readable (wrong permissions in Docker), skip it rather
# than crashing before uvicorn starts. Config still loads from env vars normally.
_env_file = Path(".env")
_readable_env_file: Path | None = _env_file if (
    _env_file.exists() and os.access(_env_file, os.R_OK)
) else None


class Settings(BaseSettings):
    """All configuration loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=_readable_env_file,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Paths
    env_file: Path = Field(default=Path(".env"), alias="ENV_FILE")
    descriptions_path: Path = Field(default=Path("rotate_keys.yaml"), alias="DESCRIPTIONS_PATH")
    data_dir: Path = Field(default=Path("/app/data"), alias="DATA_DIR")

    # Auth
    admin_password: str = Field(default="", alias="ADMIN_PASSWORD")
    reset_key: str = Field(default="", alias="RESET_KEY")
    secret_key: str = Field(default="change-me-in-production", alias="SECRET_KEY")

    # Bitwarden — all optional; if client_id + client_secret + master_password are set
    # the app will authenticate automatically on startup and re-authenticate transparently
    # when the session expires (no manual login ever needed).
    bw_session: str = Field(default="", alias="BW_SESSION")
    bw_client_id: str = Field(default="", alias="BW_CLIENT_ID")
    bw_client_secret: str = Field(default="", alias="BW_CLIENT_SECRET")
    bw_master_password: str = Field(default="", alias="BW_MASTER_PASSWORD")
    bw_server_url: str = Field(default="", alias="BW_SERVER_URL")  # for self-hosted Vaultwarden

    # Bitwarden session timeout in minutes (0 = no timeout, session lasts forever)
    bw_session_timeout_minutes: int = Field(default=0, alias="BW_SESSION_TIMEOUT_MINUTES")

    # Scanning
    scan_interval_minutes: int = Field(default=360, alias="SCAN_INTERVAL_MINUTES")
    cache_max_age_hours: float = Field(default=4.0, alias="CACHE_MAX_AGE_HOURS")
    scan_timeout_minutes: int = Field(default=60, alias="SCAN_TIMEOUT_MINUTES")

    # Auto-rotation (0 = disabled)
    auto_rotate_interval_hours: float = Field(default=0.0, alias="AUTO_ROTATE_INTERVAL_HOURS")

    # Notifications
    webhook_url: str = Field(default="", alias="WEBHOOK_URL")
    webhook_type: str = Field(default="generic", alias="WEBHOOK_TYPE")  # generic, discord, slack, gotify

    # Docker
    docker_socket: Path = Field(default=Path("/var/run/docker.sock"), alias="DOCKER_SOCKET")

    # Security — default False so plain HTTP homelab installs work out of the box.
    # Set COOKIE_HTTPS_ONLY=true if you serve over HTTPS.
    cookie_https_only: bool = Field(default=False, alias="COOKIE_HTTPS_ONLY")
    health_check_skip_ssl: bool = Field(default=False, alias="HEALTH_CHECK_SKIP_SSL")

    # Key Discovery
    discovery_search_dirs: str = Field(
        default="/mnt/user/appdata,/boot/config,/opt,/home",
        alias="DISCOVERY_SEARCH_DIRS",
    )
    discovery_skip_dirs: str = Field(
        default="proc,sys,dev,run,tmp,boot,snap,lost+found",
        alias="DISCOVERY_SKIP_DIRS",
    )

    # Cross-repo sync with glaces-automated
    sync_api_token: str = Field(default="", alias="SYNC_API_TOKEN")
    glaces_ingest_url: str = Field(default="", alias="GLACES_INGEST_URL")

    # Secrets export — written after every successful scan
    export_secrets_path: str = Field(
        default="/mnt/user/appdata/verrot/export/secrets.env",
        alias="EXPORT_SECRETS_PATH",
    )


settings = Settings()

logger = logging.getLogger("verificationrotation")

if _readable_env_file is None and _env_file.exists():
    logger.warning(
        ".env file exists but is not readable (permission denied). "
        "Configuration will be loaded from environment variables only. "
        "Fix with: chmod 644 .env"
    )

# Log auth config state so startup logs confirm what's loaded
if settings.admin_password:
    logger.info("ADMIN_PASSWORD loaded (%d chars)", len(settings.admin_password))
else:
    logger.warning(
        "ADMIN_PASSWORD is not set — all login attempts will be rejected. "
        "Set ADMIN_PASSWORD in your .env file or via the env_file: directive."
    )

# Crash on startup if the secret key is still the default.
# A persistent SECRET_KEY is required so that encrypted values in the DB
# survive container restarts and so session cookies remain valid.
if settings.secret_key == "change-me-in-production":
    logger.error(
        "FATAL: SECRET_KEY is set to the default value. "
        "Set a persistent SECRET_KEY in your .env file before starting the container."
    )
    raise SystemExit(1)

# Warn about short SECRET_KEYs — they're accepted but weak.
if len(settings.secret_key) < 32:
    logger.warning(
        "SECRET_KEY is shorter than 32 characters (%d chars). "
        "For better security, use a longer key (e.g., 64+ characters).",
        len(settings.secret_key),
    )

# Loud warning if SSL verification is disabled for health checks.
if settings.health_check_skip_ssl:
    logger.warning(
        "HEALTH_CHECK_SKIP_SSL is enabled — SSL certificates will not be verified "
        "during health checks. This is insecure and should only be used for local testing."
    )

# Warn about plaintext Bitwarden credentials in environment.
if settings.bw_master_password:
    logger.warning(
        "BW_MASTER_PASSWORD is set in the environment. Consider using Docker secrets "
        "or a file-based approach instead of plaintext environment variables for "
        "sensitive credentials. See the documentation for secure credential management."
    )

# Warn about insecure cookie settings.
if not settings.cookie_https_only:
    logger.warning(
        "COOKIE_HTTPS_ONLY is disabled — session cookies will be sent over HTTP. "
        "This is insecure and should only be used for local development."
    )
