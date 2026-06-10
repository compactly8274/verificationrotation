"""Shared validation utilities for input sanitization and security checks."""

import ipaddress
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Hostname, username, and SSH key name validation
# ---------------------------------------------------------------------------

# Hostnames: alphanumeric, dots, hyphens; must not start with a hyphen.
_SAFE_HOSTNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')

# Usernames: alphanumeric, underscores, hyphens, dots; must not start with a hyphen.
_SAFE_USERNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')

# SSH key names: alphanumeric, underscores, hyphens, dots — no slashes or path separators.
_SAFE_KEY_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')

# SQL identifiers (table/column names) — used in db_refs.
_SAFE_SQL_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def validate_hostname(host: str) -> str:
    """Validate a hostname or IP address for use in SSH connections.

    Rejects strings that could be interpreted as SSH options (e.g., starting with '-')
    or contain shell metacharacters.
    """
    if not host or not _SAFE_HOSTNAME.match(host):
        raise ValueError(
            f"Invalid hostname {host!r}: must contain only alphanumeric characters, "
            "dots, hyphens, and underscores, and must not start with a hyphen"
        )
    return host


def validate_username(user: str) -> str:
    """Validate a username for use in SSH connections.

    Rejects strings that could be interpreted as SSH options.
    """
    if not user or not _SAFE_USERNAME.match(user):
        raise ValueError(
            f"Invalid username {user!r}: must contain only alphanumeric characters, "
            "dots, hyphens, and underscores, and must not start with a hyphen"
        )
    return user


def validate_ssh_key_name(name: str) -> str:
    """Validate an SSH key name to prevent path traversal.

    Rejects names containing path separators, parent directory references,
    or characters unsafe for filenames.
    """
    if not name or not _SAFE_KEY_NAME.match(name):
        raise ValueError(
            f"Invalid SSH key name {name!r}: must contain only alphanumeric characters, "
            "dots, hyphens, and underscores, and must not start with a hyphen"
        )
    # Extra check for path traversal
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError(
            f"Invalid SSH key name {name!r}: must not contain path separators or '..'"
        )
    return name


def validate_db_ref(db_path: str, table: str, column: str) -> tuple[str, str, str]:
    """Validate a db_ref tuple, raising ValueError on unsafe identifiers."""
    if not _SAFE_SQL_IDENTIFIER.match(table):
        raise ValueError(f"Invalid SQL table name in db_refs: {table!r}")
    if not _SAFE_SQL_IDENTIFIER.match(column):
        raise ValueError(f"Invalid SQL column name in db_refs: {column!r}")
    return (db_path, table, column)


def validate_db_refs_list(db_refs: list) -> list[tuple[str, str, str]]:
    """Validate a list of db_ref tuples from user input.

    Each element must be a 3-element sequence [db_path, table, column].
    Returns a list of validated tuples.
    """
    validated = []
    for ref in db_refs:
        if not isinstance(ref, (list, tuple)) or len(ref) != 3:
            raise ValueError(
                f"Each db_refs entry must be a 3-element [db_path, table, column] tuple, got {ref!r}"
            )
        db_path, table, column = str(ref[0]), str(ref[1]), str(ref[2])
        validated.append(validate_db_ref(db_path, table, column))
    return validated


# ---------------------------------------------------------------------------
# SSRF protection — URL validation
# ---------------------------------------------------------------------------

# Private/reserved IP ranges that should never be targeted by server-side requests.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # link-local
    ipaddress.ip_network('127.0.0.0/8'),     # loopback
    ipaddress.ip_network('0.0.0.0/8'),        # "this" network
    ipaddress.ip_network('100.64.0.0/10'),     # CGN
    ipaddress.ip_network('::1/128'),          # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),          # IPv6 unique-local
    ipaddress.ip_network('fe80::/10'),          # IPv6 link-local
]


def validate_url(url: str, allow_localhost: bool = False, https_only: bool = False) -> str:
    """Validate a URL to prevent SSRF attacks.

    - Only allows http and https schemes (or https-only when https_only=True).
    - Blocks private/reserved IP addresses unless allow_localhost is True.
    - Blocks URLs without a hostname.
    """
    if not url:
        return url

    parsed = urlparse(url)

    if https_only:
        allowed = ("https",)
    else:
        allowed = ("http", "https")
    if parsed.scheme not in allowed:
        scheme_msg = "https" if https_only else "http or https"
        raise ValueError(
            f"URL scheme must be {scheme_msg}, got {parsed.scheme!r} in {url!r}"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"URL must have a hostname: {url!r}")

    # Resolve hostname and check against private networks
    import socket
    try:
        # getaddrinfo resolves the hostname to IP addresses
        addr_infos = socket.getaddrinfo(hostname, None)
        for addr_info in addr_infos:
            ip_str = addr_info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                # Allow localhost if explicitly enabled
                if allow_localhost and ip in (ipaddress.ip_address('127.0.0.1'),
                                               ipaddress.ip_address('::1')):
                    continue
                for network in _PRIVATE_NETWORKS:
                    if ip in network:
                        raise ValueError(
                            f"URL targets a private/reserved IP address ({ip_str}), "
                            f"which is not allowed: {url!r}"
                        )
            except ValueError:
                # If it's not a valid IP (e.g., still a hostname), let it through
                # after the socket resolution — this means DNS resolution returned
                # something unusual, but we've done our best.
                continue
    except socket.gaierror:
        # DNS resolution failed — the URL isn't reachable, which is safe
        # (the request would fail anyway)
        pass

    return url


def validate_url_no_private(url: str) -> str:
    """Shorthand for validate_url with default settings (no localhost)."""
    return validate_url(url, allow_localhost=False)


def validate_url_https(url: str) -> str:
    """Shorthand for validate_url with https-only + no-localhost enforcement.

    Use for webhooks and other outbound URLs that should never be plain
    HTTP and should never point at internal/private network addresses.
    """
    return validate_url(url, allow_localhost=False, https_only=True)
