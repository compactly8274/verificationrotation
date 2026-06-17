# verificationrotation

Discovers API keys from service config files across your homelab, rotates them via Bitwarden, and exports live values to a shell-sourceable `secrets.env` for downstream consumers.

## How it works

1. Walks configured appdata directories (up to 8 levels deep) matching directory names against known service signatures (Sonarr, Radarr, Prowlarr, etc.)
2. Reads the current API key / password from each detected config file
3. Stores the detected path and key value in a local SQLite database
4. Optionally rotates keys via Bitwarden (CLI or self-hosted Vaultwarden)
5. After every scan, exports all discovered values to a `secrets.env` file for other containers to consume

## Quick start

```bash
# 1. Clone
git clone https://github.com/compactly8274/verificationrotation
cd verificationrotation

# 2. Configure
cp .env.example .env
# Edit .env — set ADMIN_PASSWORD, SECRET_KEY, DATA_DIR

# 3. Start
docker compose up -d
# UI: http://<host>:8090
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ADMIN_PASSWORD` | *(required)* | Password for the web UI |
| `SECRET_KEY` | *(required)* | Persistent session key — must be 32+ chars |
| `DATA_DIR` | `/app/data` | Where the SQLite database is stored |
| `DISCOVERY_SEARCH_DIRS` | `/mnt/user/appdata,/boot/config,/opt,/home` | Comma-separated directories to scan |
| `SCAN_INTERVAL_MINUTES` | `360` | How often to re-scan automatically |
| `EXPORT_SECRETS_PATH` | `/mnt/user/appdata/verrot/export/secrets.env` | Where to write the secrets export file |
| `BW_CLIENT_ID` | *(optional)* | Bitwarden API client ID for auto-login |
| `BW_CLIENT_SECRET` | *(optional)* | Bitwarden API client secret |
| `BW_MASTER_PASSWORD` | *(optional)* | Bitwarden master password |
| `BW_SERVER_URL` | *(optional)* | Self-hosted Vaultwarden URL |
| `WEBHOOK_URL` | *(optional)* | Notification webhook (Discord, Slack, Gotify, generic) |
| `AUTO_ROTATE_INTERVAL_HOURS` | `0` | Auto-rotate interval in hours (0 = disabled) |
| `GLACES_INGEST_URL` | *(optional)* | glaces-automated ingest endpoint for cross-repo sync |
| `SYNC_API_TOKEN` | *(optional)* | Bearer token for `GLACES_INGEST_URL` |

## Single-source discovery

After every successful scan, verificationrotation writes a shell-sourceable env file to `EXPORT_SECRETS_PATH`:

```
/mnt/user/appdata/verrot/export/secrets.env
```

Each line has the form `ENV_VAR=value` (single-quoted when the value contains shell-special characters), sorted alphabetically by variable name. Example:

```
OVERSEERR_API_KEY=some32charkey
PROWLARR_API_KEY=abc123def456789a
SONARR_API_KEY=xyz789abc123456b
```

Downstream containers (e.g. glaces-automated) mount this directory read-only and source the file in their entrypoint, or reference it via `env_file:` in Compose:

```yaml
services:
  glace-generator:
    volumes:
      - /mnt/user/appdata/verrot/export:/config/secrets:ro
```

The write is atomic: the file is written to a `.tmp` sibling, fsynced, then renamed into place. Consumers always see a complete file, never a partial write.

### Backup-directory pruning

The scanner skips directories whose names suggest they are backup copies: exact matches of `backup`, `bak`, `old`, or `config-backup`, and names ending with `-backup`, `_backup`, `.backup`, `-bak`, `_bak`, `.bak`, `-old`, `_old`, or `.old`. This ensures the live config directory wins over any stale backup sitting alongside it.

Example: given both `prowlarr-config-backup/` and `prowlarr/`, the scanner records the path from `prowlarr/config.xml` and ignores the backup directory entirely.

### Migration note for existing users

If your database was populated before the backup-pruning fix was added (commit `995d394`), the `detected_config_path` column for some services may still point to a backup directory (e.g. `/mnt/user/appdata/prowlarr-config-backup/config.xml`).

To correct this:

1. Open the verificationrotation UI → **Keys** tab
2. Click **Detect service paths** (or wait for the next scheduled scan)
3. The scanner will skip backup directories and record the live paths
4. The next export cycle writes correct values to `secrets.env`

No database migration is required — the scan overwrites the stored paths in place.

## Local development

```bash
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8090
```

Tests:

```bash
python -m unittest discover tests -v
```
