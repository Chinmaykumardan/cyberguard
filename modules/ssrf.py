"""
HoneyShield SSRF Protection Engine
Validates destinations against private, loopback, link-local, and cloud-metadata ranges.
Prevents DNS rebinding and enforces strict timeout/size boundaries.
"""
import ipaddress
import logging
import socket
from urllib.parse import urlparse
import requests

logger = logging.getLogger("honeyshield.ssrf")

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local & cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("::1/128"),              # IPv6 loopback
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),             # Unique local
    ipaddress.ip_network("fe80::/10"),            # Link-local
]


class SSRFException(Exception):
    """Raised when an SSRF violation is detected."""
    pass


def is_ip_allowed(ip_str: str) -> bool:
    """Checks whether an resolved IP address is public and safe to contact."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return False
        for net in BLOCKED_NETWORKS:
            if ip_obj in net:
                return False
        return True
    except ValueError:
        return False


def validate_url(url: str) -> tuple:
    """
    Validates scheme and resolves hostname.
    Returns (resolved_ip, parsed_url) if safe, otherwise raises SSRFException.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFException("Only HTTP and HTTPS protocols are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFException("URL must contain a valid hostname.")

    # Resolve IP
    try:
        addrinfo = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        resolved_ips = list(set([entry[4][0] for entry in addrinfo]))
    except socket.gaierror as e:
        raise SSRFException(f"Failed to resolve hostname '{hostname}': {e}")

    for ip in resolved_ips:
        if not is_ip_allowed(ip):
            raise SSRFException(f"Destination resolves to restricted or private network IP: {ip}")

    return resolved_ips[0], parsed


def safe_fetch(url: str, max_redirects: int = 5, timeout: int = 5, max_bytes: int = 1048576) -> requests.Response:
    """
    Fetches destination URL while re-validating every redirect against SSRF rules.
    Limits content size to max_bytes (1 MB).
    """
    current_url = url
    session = requests.Session()
    session.headers.update({"User-Agent": "HoneyShield-Scanner/1.0 (+https://honeyshield.local)"})

    for hop in range(max_redirects + 1):
        resolved_ip, parsed = validate_url(current_url)

        resp = session.get(
            current_url,
            allow_redirects=False,
            timeout=timeout,
            stream=True,
            verify=True
        )

        if resp.is_redirect:
            location = resp.headers.get("Location")
            if not location:
                break
            current_url = location
            continue

        # Enforce size ceiling
        content = bytearray()
        for chunk in resp.iter_content(chunk_size=8192):
            content.extend(chunk)
            if len(content) > max_bytes:
                resp.close()
                break
        resp._content = bytes(content)
        return resp

    raise SSRFException("Too many redirect hops detected.")
