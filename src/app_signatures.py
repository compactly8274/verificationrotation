"""Known homelab service signatures for automatic config-path detection.

Each entry maps a service ID (matching rotate_keys.yaml) to detection rules:
  dir_patterns          — glob(s) matched case-insensitively against directory
                          names found under DISCOVERY_SEARCH_DIRS
  config_file           — path relative to the matched directory
  config_file_candidates — tried in order when multiple locations are possible
  format                — "ini" | "json" | "yaml" | "toml" | "env" | "arr_xml" | "xml_tag"
  docker_name           — default container name for stop/start during rotation
  password_hash         — "bcrypt" | "sha256_double"; when set, auto_fetch
                          always returns None (can't reverse a hash), and
                          auto_write hashes the generated value before writing
  xml_tag               — element name used with format="xml_tag"
"""

from typing import Any

APP_SIGNATURES: dict[str, dict[str, Any]] = {
    # ── *arr stack (config.xml with <ApiKey>) ────────────────────────────────
    "sonarr": {
        "dir_patterns": ["sonarr*"],
        "config_file": "config.xml",
        "format": "arr_xml",
        "docker_name": "sonarr",
    },
    "radarr": {
        "dir_patterns": ["radarr*"],
        "config_file": "config.xml",
        "format": "arr_xml",
        "docker_name": "radarr",
    },
    "lidarr": {
        "dir_patterns": ["lidarr*"],
        "config_file": "config.xml",
        "format": "arr_xml",
        "docker_name": "lidarr",
    },
    "readarr": {
        "dir_patterns": ["readarr*"],
        "config_file": "config.xml",
        "format": "arr_xml",
        "docker_name": "readarr",
    },
    "prowlarr": {
        "dir_patterns": ["prowlarr*"],
        "config_file": "config.xml",
        "format": "arr_xml",
        "docker_name": "prowlarr",
    },
    "whisparr": {
        "dir_patterns": ["whisparr*"],
        "config_file": "config.xml",
        "format": "arr_xml",
        "docker_name": "whisparr",
    },
    # ── Usenet / torrent ─────────────────────────────────────────────────────
    "sabnzbd": {
        "dir_patterns": ["sabnzbd*"],
        "config_file": "sabnzbd.ini",
        "format": "ini",
        "ini_section": "misc",
        "ini_key": "api_key",
        "docker_name": "sabnzbd",
    },
    "nzbget": {
        "dir_patterns": ["nzbget*"],
        "config_file": "nzbget.conf",
        "format": "env",
        "env_key": "ControlPassword",
        "docker_name": "nzbget",
    },
    "transmission": {
        "dir_patterns": ["transmission*"],
        "config_file_candidates": [
            "settings.json",
            "config/settings.json",
        ],
        "format": "json",
        "json_path": ["rpc-username"],
        "docker_name": "transmission",
    },
    # ── Indexers / automation ─────────────────────────────────────────────────
    "jackett": {
        "dir_patterns": ["jackett*"],
        # Jackett nests its config in a subdir named "Jackett"
        "config_file_candidates": ["Jackett/ServerConfig.json", "ServerConfig.json"],
        "format": "json",
        "json_path": ["APIKey"],
        "docker_name": "jackett",
    },
    "nzbhydra2": {
        "dir_patterns": ["nzbhydra*", "nzbhydra2*"],
        "config_file_candidates": [
            "nzbhydra.yml",
            "config/nzbhydra.yml",
            "data/nzbhydra.yml",
        ],
        "format": "yaml",
        "yaml_path": ["main", "apiKey"],
        "docker_name": "nzbhydra2",
    },
    "autobrr": {
        "dir_patterns": ["autobrr*"],
        "config_file": "config.toml",
        "format": "toml",
        "toml_key": "apiSecret",
        "docker_name": "autobrr",
    },
    "mylar3": {
        "dir_patterns": ["mylar*", "mylar3*"],
        "config_file_candidates": ["mylar.ini", "config/mylar.ini"],
        "format": "ini",
        "ini_section": "Interface",
        "ini_key": "api_key",
        "docker_name": "mylar3",
    },
    # ── Request management ────────────────────────────────────────────────────
    "overseerr": {
        "dir_patterns": ["overseerr*"],
        "config_file": "settings.json",
        "format": "json",
        "json_path": ["apiKey"],
        "docker_name": "overseerr",
    },
    "jellyseerr": {
        "dir_patterns": ["jellyseerr*"],
        "config_file": "settings.json",
        "format": "json",
        "json_path": ["apiKey"],
        "docker_name": "jellyseerr",
    },
    # ── Subtitles / metadata ──────────────────────────────────────────────────
    "bazarr": {
        "dir_patterns": ["bazarr*"],
        "config_file_candidates": ["config.yaml", "config/config.yaml"],
        "format": "yaml",
        "yaml_path": ["auth", "apikey"],
        "docker_name": "bazarr",
    },
    # ── Media stats ───────────────────────────────────────────────────────────
    "tautulli": {
        "dir_patterns": ["tautulli*"],
        "config_file": "config.ini",
        "format": "ini",
        "ini_section": "General",
        "ini_key": "api_key",
        "docker_name": "tautulli",
    },
    # ── DNS / ad-block ────────────────────────────────────────────────────────
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
    # ── Monitoring / observability ────────────────────────────────────────────
    "grafana": {
        "dir_patterns": ["grafana*"],
        "config_file_candidates": [
            "grafana.ini",
            "config/grafana.ini",
            "conf/defaults.ini",
        ],
        "format": "ini",
        "ini_section": "security",
        "ini_key": "admin_password",
        "docker_name": "grafana",
    },
    "netdata": {
        "dir_patterns": ["netdata*"],
        "config_file_candidates": [
            "netdata.conf",
            "etc/netdata/netdata.conf",
        ],
        "format": "ini",
        "ini_section": "web",
        "ini_key": "api key",
        "docker_name": "netdata",
    },
    # ── Password managers / auth ──────────────────────────────────────────────
    "vaultwarden": {
        "dir_patterns": ["vaultwarden*", "bitwarden*"],
        "config_file_candidates": [".env", "env"],
        "format": "env",
        "env_key": "ADMIN_TOKEN",
        "docker_name": "vaultwarden",
    },
    "authelia": {
        "dir_patterns": ["authelia*"],
        "config_file_candidates": [
            "configuration.yml",
            "config/configuration.yml",
            "configuration.yaml",
        ],
        "format": "yaml",
        "yaml_path": ["jwt_secret"],
        "docker_name": "authelia",
    },
    # ── Document / book management ────────────────────────────────────────────
    "paperless": {
        "dir_patterns": ["paperless*"],
        "config_file_candidates": [
            "docker-compose.env",
            ".env",
            "paperless.conf",
        ],
        "format": "env",
        "env_key": "PAPERLESS_SECRET_KEY",
        "docker_name": "paperless-ngx",
    },
    "kavita": {
        "dir_patterns": ["kavita*"],
        "config_file_candidates": [
            "config/appsettings.json",
            "appsettings.json",
        ],
        "format": "json",
        "json_path": ["TokenKey"],
        "docker_name": "kavita",
    },
    "komga": {
        "dir_patterns": ["komga*"],
        "config_file_candidates": [
            "application.yml",
            "config/application.yml",
        ],
        "format": "yaml",
        "yaml_path": ["komga", "user", "password"],
        "docker_name": "komga",
    },
    # ── Music / P2P ───────────────────────────────────────────────────────────
    "slskd": {
        "dir_patterns": ["slskd*"],
        "config_file_candidates": [
            "slskd.yml",
            "config/slskd.yml",
            "slskd.yaml",
        ],
        "format": "yaml",
        "yaml_path": ["web", "authentication", "apiKey"],
        "docker_name": "slskd",
    },
    # ── Git / dev ─────────────────────────────────────────────────────────────
    "gitea": {
        "dir_patterns": ["gitea*"],
        "config_file_candidates": [
            "gitea/conf/app.ini",
            "conf/app.ini",
            "app.ini",
        ],
        "format": "ini",
        "ini_section": "security",
        "ini_key": "SECRET_KEY",
        "docker_name": "gitea",
    },
    "forgejo": {
        "dir_patterns": ["forgejo*"],
        "config_file_candidates": [
            "forgejo/conf/app.ini",
            "conf/app.ini",
            "app.ini",
        ],
        "format": "ini",
        "ini_section": "security",
        "ini_key": "SECRET_KEY",
        "docker_name": "forgejo",
    },
    # ── Sync ──────────────────────────────────────────────────────────────────
    "syncthing": {
        "dir_patterns": ["syncthing*"],
        "config_file_candidates": [
            "config.xml",
            "config/config.xml",
            ".config/syncthing/config.xml",
        ],
        "format": "xml_tag",
        "xml_tag": "apikey",
        "docker_name": "syncthing",
    },
    # ── RSS ───────────────────────────────────────────────────────────────────
    "miniflux": {
        "dir_patterns": ["miniflux*"],
        "config_file_candidates": [
            ".env",
            "miniflux.env",
            "config/miniflux.env",
        ],
        "format": "env",
        "env_key": "ADMIN_PASSWORD",
        "docker_name": "miniflux",
    },
    # ── VPN / proxy ───────────────────────────────────────────────────────────
    "gluetun": {
        "dir_patterns": ["gluetun*"],
        "config_file_candidates": [".env", "env"],
        "format": "env",
        "env_key": "HTTP_CONTROL_SERVER_API_KEY",
        "docker_name": "gluetun",
    },
    # ── File management ───────────────────────────────────────────────────────
    "filebrowser": {
        "dir_patterns": ["filebrowser*", "file-browser*"],
        "config_file_candidates": [
            ".filebrowser.json",
            "filebrowser.json",
            "config/filebrowser.json",
        ],
        "format": "json",
        "json_path": ["password"],
        "docker_name": "filebrowser",
    },
    # ── Smart home ────────────────────────────────────────────────────────────
    "homebridge": {
        "dir_patterns": ["homebridge*"],
        "config_file_candidates": [
            "config.json",
            ".homebridge/config.json",
        ],
        "format": "json",
        "json_path": ["bridge", "pin"],
        "docker_name": "homebridge",
    },
    # ── Photos ────────────────────────────────────────────────────────────────
    "immich": {
        "dir_patterns": ["immich*"],
        "config_file_candidates": [
            ".env",
            "docker-compose.env",
        ],
        "format": "env",
        "env_key": "DB_PASSWORD",
        "docker_name": "immich-server",
    },
    # ── Dashboards ────────────────────────────────────────────────────────────
    "homepage": {
        "dir_patterns": ["homepage*"],
        "config_file_candidates": [
            "config/services.yaml",
            "services.yaml",
        ],
        "format": "yaml",
        "yaml_path": ["apiKey"],
        "docker_name": "homepage",
    },
}
