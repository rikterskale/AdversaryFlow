from __future__ import annotations

from urllib.parse import urlparse


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def host_is_allowed(host: str, allowed_domains: set[str]) -> bool:
    host = normalize_host(host)
    for allowed in allowed_domains:
        allowed = normalize_host(allowed)
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


def url_is_allowlisted(url: str, allowed_domains: set[str]) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and host_is_allowed(parsed.hostname, allowed_domains)
    )
