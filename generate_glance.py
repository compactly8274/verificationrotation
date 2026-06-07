#!/usr/bin/env python3
"""Generate a Glance dashboard YAML by auto-discovering Docker containers.

Supports multiple Docker hosts (Unix socket and/or TCP) and deduplicates
containers that are seen via more than one connection pointing at the same
daemon.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import docker
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GLANCE_LABEL_PREFIX = "glance."
GLANCE_ENABLE_LABEL = "glance.enable"
GLANCE_NAME_LABEL = "glance.name"
GLANCE_URL_LABEL = "glance.url"
GLANCE_ICON_LABEL = "glance.icon"
GLANCE_DESCRIPTION_LABEL = "glance.description"
GLANCE_GROUP_LABEL = "glance.group"

CACHE_VERSION = 1


@dataclass
class HostConfig:
    """Configuration for a single Docker host connection."""

    name: str
    socket: Optional[str] = None
    tcp_url: Optional[str] = None
    tls_verify: bool = False
    cert_path: Optional[str] = None
    default_url_template: str = "http://{host}:{port}"
    include_unlabelled: bool = False

    @property
    def docker_url(self) -> str:
        if self.tcp_url:
            return self.tcp_url
        if self.socket:
            return f"unix://{self.socket}"
        return "unix:///var/run/docker.sock"


@dataclass
class ContainerInfo:
    """Discovered service information extracted from a container."""

    name: str
    url: str
    icon: str = ""
    description: str = ""
    group: str = "Services"
    host: str = ""
    container_id: str = ""


# ---------------------------------------------------------------------------
# GitHub cache helpers
# ---------------------------------------------------------------------------

def load_github_cache(cache_path: Path) -> dict:
    """Load the persistent on-disk cache (keyed by container ID)."""
    if cache_path.exists():
        try:
            with cache_path.open() as fh:
                data = json.load(fh)
            if data.get("version") == CACHE_VERSION:
                return data
        except Exception as exc:  # noqa: BLE001
            logging.warning("Could not read cache %s: %s", cache_path, exc)
    return {"version": CACHE_VERSION, "entries": {}}


def save_github_cache(cache: dict, cache_path: Path) -> None:
    """Persist the cache to disk."""
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w") as fh:
            json.dump(cache, fh, indent=2)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Could not write cache %s: %s", cache_path, exc)


# ---------------------------------------------------------------------------
# Docker discovery
# ---------------------------------------------------------------------------

def _make_client(host: HostConfig) -> docker.DockerClient:
    """Create a DockerClient for the given HostConfig."""
    kwargs: dict = {"base_url": host.docker_url}
    if host.tls_verify and host.cert_path:
        tls_config = docker.tls.TLSConfig(
            client_cert=(
                os.path.join(host.cert_path, "cert.pem"),
                os.path.join(host.cert_path, "key.pem"),
            ),
            ca_cert=os.path.join(host.cert_path, "ca.pem"),
            verify=host.tls_verify,
        )
        kwargs["tls"] = tls_config
    return docker.DockerClient(**kwargs)


def _infer_url(container, host: HostConfig) -> Optional[str]:
    """Try to derive a service URL from exposed ports or labels."""
    labels = container.labels or {}

    if GLANCE_URL_LABEL in labels:
        return labels[GLANCE_URL_LABEL]

    # Derive hostname from TCP URL or fall back to localhost.
    docker_host = "localhost"
    if host.tcp_url:
        m = re.match(r"[a-z]+://([^:/]+)", host.tcp_url)
        if m:
            docker_host = m.group(1)

    ports = container.ports or {}
    for container_port, bindings in sorted(ports.items()):
        if bindings:
            host_port = bindings[0].get("HostPort", "")
            if host_port:
                return host.default_url_template.format(
                    host=docker_host, port=host_port
                )
    return None


def discover_containers(host: HostConfig, client: docker.DockerClient) -> list[ContainerInfo]:
    containers = []
    seen_ids: set[str] = set()
    try:
        for c in client.containers.list():
            if c.id in seen_ids:
                logging.debug("Skipping duplicate container %s on %s", c.name, host.name)
                continue
            seen_ids.add(c.id)
            name = c.name.lstrip("/")
            labels = c.labels or {}

            # Skip containers that have explicitly opted out.
            if labels.get(GLANCE_ENABLE_LABEL, "").lower() == "false":
                logging.debug("Container %s opted out via label", name)
                continue

            # Skip unlabelled containers unless the host allows them.
            has_glance_labels = any(
                k.startswith(GLANCE_LABEL_PREFIX) for k in labels
            )
            if not has_glance_labels and not host.include_unlabelled:
                logging.debug("Skipping unlabelled container %s on %s", name, host.name)
                continue

            url = _infer_url(c, host)
            if not url:
                logging.debug("No URL for container %s on %s; skipping", name, host.name)
                continue

            display_name = labels.get(GLANCE_NAME_LABEL, name)
            icon = labels.get(GLANCE_ICON_LABEL, "")
            description = labels.get(GLANCE_DESCRIPTION_LABEL, "")
            group = labels.get(GLANCE_GROUP_LABEL, "Services")

            containers.append(
                ContainerInfo(
                    name=display_name,
                    url=url,
                    icon=icon,
                    description=description,
                    group=group,
                    host=host.name,
                    container_id=c.id,
                )
            )
    except docker.errors.DockerException as exc:
        logging.error("Error listing containers on host %s: %s", host.name, exc)
    return containers


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def _load_exclude_patterns(env_var: str = "GLANCE_EXCLUDE") -> list[re.Pattern]:
    raw = os.environ.get(env_var, "")
    patterns = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                patterns.append(re.compile(part, re.IGNORECASE))
            except re.error as exc:
                logging.warning("Invalid exclude pattern %r: %s", part, exc)
    return patterns


def _is_excluded(container: ContainerInfo, patterns: list[re.Pattern]) -> bool:
    return any(p.search(container.name) or p.search(container.url) for p in patterns)


# ---------------------------------------------------------------------------
# YAML generation
# ---------------------------------------------------------------------------

def _build_glance_yaml(services_by_group: dict[str, list[ContainerInfo]]) -> str:
    """Render the Glance services YAML fragment."""
    columns = []
    for group_name, services in sorted(services_by_group.items()):
        widgets = []
        for svc in sorted(services, key=lambda s: s.name.lower()):
            widget: dict = {"type": "service", "name": svc.name, "url": svc.url}
            if svc.icon:
                widget["icon"] = svc.icon
            if svc.description:
                widget["description"] = svc.description
            widgets.append(widget)
        columns.append({"title": group_name, "widgets": widgets})

    return yaml.dump(
        {"columns": columns},
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _load_host_configs() -> list[HostConfig]:
    """Build host configurations from environment variables.

    Reads DOCKER_HOSTS as a comma-separated list of entries.  Each entry
    can be:
      - ``socket:/path/to/docker.sock`` (Unix socket)
      - ``tcp://host:port`` (TCP, optionally with TLS)

    Falls back to the local Docker socket if the variable is absent.
    """
    raw = os.environ.get("DOCKER_HOSTS", "")
    hosts: list[HostConfig] = []
    include_unlabelled = os.environ.get("GLANCE_INCLUDE_UNLABELLED", "").lower() in (
        "1", "true", "yes",
    )

    if not raw:
        hosts.append(
            HostConfig(
                name="local",
                socket="/var/run/docker.sock",
                include_unlabelled=include_unlabelled,
            )
        )
        return hosts

    for idx, entry in enumerate(raw.split(",")):
        entry = entry.strip()
        if not entry:
            continue
        if entry.startswith("socket:"):
            socket_path = entry[len("socket:"):]
            hosts.append(
                HostConfig(
                    name=f"socket-{idx}",
                    socket=socket_path,
                    include_unlabelled=include_unlabelled,
                )
            )
        elif entry.startswith("tcp://") or entry.startswith("https://"):
            hosts.append(
                HostConfig(
                    name=f"tcp-{idx}",
                    tcp_url=entry,
                    tls_verify=entry.startswith("https://"),
                    cert_path=os.environ.get("DOCKER_CERT_PATH"),
                    include_unlabelled=include_unlabelled,
                )
            )
        else:
            logging.warning("Unrecognised DOCKER_HOSTS entry %r; skipping", entry)

    return hosts


def run_once(
    output_path: Path,
    cache_path: Path,
    exclude_patterns: Optional[list[re.Pattern]] = None,
) -> None:
    """Discover containers, build the YAML, and write it to *output_path*."""
    if exclude_patterns is None:
        exclude_patterns = _load_exclude_patterns()

    host_configs = _load_host_configs()
    cache = load_github_cache(cache_path)

    all_containers: list[ContainerInfo] = []
    for host in host_configs:
        logging.info("Connecting to Docker host %s (%s)", host.name, host.docker_url)
        try:
            client = _make_client(host)
            client.ping()
        except Exception as exc:  # noqa: BLE001
            logging.error("Cannot connect to Docker host %s: %s", host.name, exc)
            continue

        discovered = discover_containers(host, client)
        logging.info(
            "Discovered %d container(s) on host %s", len(discovered), host.name
        )
        all_containers.extend(discovered)

    included: list[ContainerInfo] = []
    for container in all_containers:
        if _is_excluded(container, exclude_patterns):
            logging.info("Excluding %s (%s)", container.name, container.url)
            continue
        # Update cache entry.
        cache.setdefault("entries", {})[container.container_id] = {
            "name": container.name,
            "url": container.url,
            "last_seen": int(time.time()),
        }
        included.append(container)

    # Deduplicate: same service discovered via both socket and TCP pointing to the same daemon.
    _seen_urls: set[str] = set()
    _deduped: list[ContainerInfo] = []
    for _c in included:
        if _c.url in _seen_urls:
            logging.debug("Deduplicating %s (url=%s)", _c.name, _c.url)
            continue
        _seen_urls.add(_c.url)
        _deduped.append(_c)
    if len(_deduped) < len(included):
        logging.info("Deduplication removed %d service(s) with matching URLs", len(included) - len(_deduped))
    included = _deduped

    save_github_cache(cache, cache_path)

    services_by_group: dict[str, list[ContainerInfo]] = {}
    for svc in included:
        services_by_group.setdefault(svc.group, []).append(svc)

    glance_yaml = _build_glance_yaml(services_by_group)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(glance_yaml, encoding="utf-8")
    logging.info(
        "Wrote %d service(s) across %d group(s) to %s",
        len(included),
        len(services_by_group),
        output_path,
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a Glance dashboard YAML from running Docker containers."
    )
    parser.add_argument(
        "--output",
        default=os.environ.get("GLANCE_OUTPUT", "glance-services.yml"),
        help="Path to write the generated YAML (default: glance-services.yml)",
    )
    parser.add_argument(
        "--cache",
        default=os.environ.get("GLANCE_CACHE", ".glance-cache.json"),
        help="Path to the JSON cache file (default: .glance-cache.json)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(os.environ.get("GLANCE_INTERVAL", "0")),
        help="If >0, re-run every N seconds (daemon mode)",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    output_path = Path(args.output)
    cache_path = Path(args.cache)

    if args.interval > 0:
        logging.info("Running in daemon mode (interval=%ds)", args.interval)
        while True:
            run_once(output_path, cache_path)
            time.sleep(args.interval)
    else:
        run_once(output_path, cache_path)


if __name__ == "__main__":
    main()
