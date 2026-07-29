"""SSRF guard (MVP 15.1) — block localhost, private, link-local and cloud metadata.

Checked before and after DNS resolution. Only http(s) allowed.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# cloud metadata endpoints that must never be fetched
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.100.200"}


class SSRFError(ValueError):
    """Raised when a URL/target resolves to a forbidden address."""


def _ip_is_forbidden(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> refuse
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or ip in _METADATA_HOSTS
    )


def validate_url(url: str) -> None:
    """Raise SSRFError if the URL scheme/host is not allowed. Pre-DNS check."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"scheme not allowed: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise SSRFError("missing host")
    if host in _METADATA_HOSTS or host in ("localhost",):
        raise SSRFError(f"forbidden host: {host!r}")
    # if host is a literal IP, check it directly
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return  # hostname — resolved-IP check happens in validate_resolved
    if _ip_is_forbidden(host):
        raise SSRFError(f"forbidden ip literal: {host!r}")


def validate_resolved(host: str) -> None:
    """Resolve host and refuse if ANY resolved address is forbidden. Post-DNS."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SSRFError(f"dns resolution failed for {host!r}: {e}") from e
    for info in infos:
        ip = str(info[4][0])
        if _ip_is_forbidden(ip):
            raise SSRFError(f"host {host!r} resolves to forbidden ip {ip}")
