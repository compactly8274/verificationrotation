"""Known homelab service signatures for automatic config-path detection.

Each entry maps a service ID (matching rotate_keys.yaml) to detection rules:
  dir_patterns          — glob(s) matched case-insensitively against directory
                          names found under DISCOVERY_SEARCH_DIRS
  config_file           — path relative to the matched directory
  config_file_candidates — tried in order when multiple locations are possible
  format                — "ini" | "json" | "yaml" | "toml" | "env"
  docker_name           — default container name for stop/start during rotation
  password_hash         — "bcrypt" | "sha256_double"; when set, auto_fetch
                          always returns None (can't reverse a hash), and
                          auto_write hashes the generated value before writing
"""

from typing import Any

APP_SIGNATURES: dict[str, dict[str, Any]] = {
    "sabnzbd": {
        "dir_patterns": ["sabnzbd*"],
        "config_file": "sabnzbd.ini",
        "format": "ini",
        "ini_section": "misc",
        "ini_key": "api_key",
        "docker_name": "sabnzbd",
    },
    "jackett": {
        "dir_patterns": ["jackett*"],
        # Jackett nests its config in a subdir named "Jackett"
        "config_file_candidates": ["Jackett/ServerConfig.json", "ServerConfig.json"],
        "format": "json",
        "json_path": ["APIKey"],
        "docker_name": "jackett",
    },
    "autobrr": {
        "dir_patterns": ["autobrr*"],
        "config_file": "config.toml",
        "format": "toml",
        "toml_key": "apiSecret",
        "docker_name": "autobrr",
    },
    "tautulli": {
        "dir_patterns": ["tautulli*"],
        "config_file": "config.ini",
        "format": "ini",
        "ini_section": "General",
        "ini_key": "api_key",
        "docker_name": "tautulli",
    },
    "overseerr": {
        "dir_patterns": ["overseerr*"],
        "config_file": "settings.json",
        "format": "json",
        "json_path": ["apiKey"],
        "docker_name": "overseerr",
    },
    "bazarr": {
        "dir_patterns": ["bazarr*"],
        "config_file_candidates": ["config.yaml", "config/config.yaml"],
        "format": "yaml",
        "yaml_path": ["auth", "apikey"],
        "docker_name": "bazarr",
    },
    "jellyseerr": {
        "dir_patterns": ["jellyseerr*"],
        "config_file": "settings.json",
        "format": "json",
        "json_path": ["apiKey"],
        "docker_name": "jellyseerr",
    },
    "adguard": {
        "dir_patterns": ["adguard*", "adguardhome*"],
        "config_file": "AdGuardHome.yaml",
        "format": "yaml",
        "yaml_path": ["users", 0, "password"],
        "password_hash": "bcrypt",
        "docker_name": "adguardhome",
    },
    "pihole": {
        "dir_patterns": ["pihole*", "pi-hole*"],
        "config_file_candidates": ["setupVars.conf", "etc-pihole/setupVars.conf"],
        "format": "env",
        "env_key": "WEBPASSWORD",
        "password_hash": "sha256_double",
        "docker_name": "pihole",
    },
}
