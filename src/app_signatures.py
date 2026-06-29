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
    # ── Hunting / automation ──────────────────────────────────────────────────
    "huntarr": {
        "dir_patterns": ["huntarr*"],
        "config_file_candidates": ["settings.json", "config/settings.json"],
        "format": "json",
        "json_path": ["api_key"],
        "docker_name": "huntarr",
    },
    "houndarr": {
        "dir_patterns": ["houndarr*"],
        "config_file_candidates": ["settings.json", "config/settings.json"],
        "format": "json",
        "json_path": ["api_key"],
        "docker_name": "houndarr",
    },
    "kapowarr": {
        "dir_patterns": ["kapowarr*"],
        "config_file_candidates": ["db/kapowarr.db", "kapowarr.db"],
        "format": "sqlite",
        "sqlite_table": "settings",
        "sqlite_column": "value",
        "sqlite_where": "key='api_key'",
        "docker_name": "kapowarr",
    },
    # ── Secret / backup managers ──────────────────────────────────────────────
    "lazywarden_bw_password": {
        "dir_patterns": ["lazywarden*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "BW_PASSWORD",
        "docker_name": "lazywarden",
    },
    "lazywarden_bw_totp": {
        "dir_patterns": ["lazywarden*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "BW_TOTP_SECRET",
        "docker_name": "lazywarden",
    },
    "lazywarden_enc_password": {
        "dir_patterns": ["lazywarden*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "ENCRYPTION_PASSWORD",
        "docker_name": "lazywarden",
    },
    "lazywarden_zip_password": {
        "dir_patterns": ["lazywarden*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "ZIP_PASSWORD",
        "docker_name": "lazywarden",
    },
    "lazywarden_todoist": {
        "dir_patterns": ["lazywarden*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "TODOIST_TOKEN",
        "docker_name": "lazywarden",
    },
    # ── AI / chat ─────────────────────────────────────────────────────────────
    "librechat_serper": {
        "dir_patterns": ["librechat*"],
        "config_file_candidates": [".env", "librechat.env"],
        "format": "env",
        "env_key": "SERPER_API_KEY",
        "docker_name": "librechat",
    },
    "librechat_jina": {
        "dir_patterns": ["librechat*"],
        "config_file_candidates": [".env", "librechat.env"],
        "format": "env",
        "env_key": "JINA_API_KEY",
        "docker_name": "librechat",
    },
    "librechat_jwt": {
        "dir_patterns": ["librechat*"],
        "config_file_candidates": [".env", "librechat.env"],
        "format": "env",
        "env_key": "JWT_SECRET",
        "docker_name": "librechat",
    },
    # ── Media-state tracking ──────────────────────────────────────────────────
    "watchstate": {
        "dir_patterns": ["watchstate*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "WS_API_KEY",
        "docker_name": "watchstate",
    },
    "watchstate_secret": {
        "dir_patterns": ["watchstate*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "WS_SYSTEM_SECRET",
        "docker_name": "watchstate",
    },
    # ── Terminal / session ────────────────────────────────────────────────────
    "termix_jwt": {
        "dir_patterns": ["termix*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "JWT_SECRET",
        "docker_name": "termix",
    },
    "termix_db_key": {
        "dir_patterns": ["termix*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "DATABASE_KEY",
        "docker_name": "termix",
    },
    "termix_auth_token": {
        "dir_patterns": ["termix*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "INTERNAL_AUTH_TOKEN",
        "docker_name": "termix",
    },
    "termix_enc_key": {
        "dir_patterns": ["termix*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "ENCRYPTION_KEY",
        "docker_name": "termix",
    },
    # ── AI paperless helpers ──────────────────────────────────────────────────
    "paperless_ai_key": {
        "dir_patterns": ["paperless-ai*", "paperlessai*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "API_KEY",
        "docker_name": "paperless-ai",
    },
    "paperless_ai_jwt": {
        "dir_patterns": ["paperless-ai*", "paperlessai*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "JWT_SECRET",
        "docker_name": "paperless-ai",
    },
    # ── Nginx Proxy Manager (SQLite) ──────────────────────────────────────────
    "npm": {
        "dir_patterns": ["nginx-proxy-manager*", "npm*"],
        "config_file_candidates": ["data/database.sqlite", "database.sqlite"],
        "format": "sqlite",
        "sqlite_table": "user",
        "sqlite_column": "secret",
        "sqlite_where": "id=1",
        "docker_name": "nginx-proxy-manager",
    },
    # ── Budget ────────────────────────────────────────────────────────────────
    "actual_budget": {
        "dir_patterns": ["actual*", "actual-budget*"],
        "config_file_candidates": ["server-files/account-db/sessions.sqlite", "data/server-files/account-db/sessions.sqlite"],
        "format": "sqlite",
        "sqlite_table": "sessions",
        "sqlite_column": "token",
        "docker_name": "actual-budget",
    },
    # ── Profilarr ─────────────────────────────────────────────────────────────
    "profilarr": {
        "dir_patterns": ["profilarr*"],
        "config_file_candidates": ["config.json", "config/config.json"],
        "format": "json",
        "json_path": ["api_key"],
        "docker_name": "profilarr",
    },
    # ── Media analysis ────────────────────────────────────────────────────────
    "tdarr": {
        "dir_patterns": ["tdarr*"],
        "config_file_candidates": ["server/logs/Tdarr_DB/Tdarr_DB.db", "Tdarr_DB.db"],
        "format": "sqlite",
        "sqlite_table": "settings",
        "sqlite_column": "value",
        "sqlite_where": "key='serverPort'",
        "docker_name": "tdarr",
    },
    # ── Maintenance ───────────────────────────────────────────────────────────
    "maintainerr": {
        "dir_patterns": ["maintainerr*"],
        "config_file_candidates": ["data/db.sqlite3", "db.sqlite3"],
        "format": "sqlite",
        "sqlite_table": "settings",
        "sqlite_column": "value",
        "sqlite_where": "key='apiKey'",
        "docker_name": "maintainerr",
    },
    # ── YAML-based ────────────────────────────────────────────────────────────
    "kometa": {
        "dir_patterns": ["kometa*", "plex-meta-manager*"],
        "config_file_candidates": ["config/config.yml", "config.yml"],
        "format": "yaml",
        "yaml_path": ["plex", "token"],
        "docker_name": "kometa",
    },
    "scrutiny": {
        "dir_patterns": ["scrutiny*"],
        "config_file_candidates": ["config/scrutiny.yaml", "scrutiny.yaml"],
        "format": "yaml",
        "yaml_path": ["web", "api_key"],
        "docker_name": "scrutiny",
    },
    "bookstack": {
        "dir_patterns": ["bookstack*"],
        "config_file_candidates": [".env", "bookstack.env"],
        "format": "env",
        "env_key": "APP_KEY",
        "docker_name": "bookstack",
    },
    "booklore": {
        "dir_patterns": ["booklore*"],
        "config_file_candidates": [".env", "config/.env"],
        "format": "env",
        "env_key": "JWT_SECRET",
        "docker_name": "booklore",
    },
}
