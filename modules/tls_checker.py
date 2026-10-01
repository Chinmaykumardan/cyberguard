"""
HoneyShield SSL/TLS Certificate Checker Module (Phase 4 foundation)
Inspects public server certificates, cipher suites, expiration dates, and trust chains.
"""
import ssl
import socket
import logging
from datetime import datetime

logger = logging.getLogger("honeyshield.tls_checker")


def check_hostname_tls(hostname: str, port: int = 443) -> dict:
    """Connects to public hostname via TLS and inspects certificate metadata."""
    clean_host = hostname.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if not clean_host:
        return {"error": "Invalid hostname"}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((clean_host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse expiry
                not_after_str = cert.get("notAfter")
                days_left = 90
                if not_after_str:
                    exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = max(0, (exp_date - datetime.utcnow()).days)

                return {
                    "hostname": clean_host,
                    "port": port,
                    "protocol": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "expiry_days": days_left,
                    "grade": "A+" if days_left > 30 and version in ("TLSv1.2", "TLSv1.3") else "B",
                    "verdict": "Certificate healthy" if days_left > 14 else "Expiring soon",
                    "chain_valid": True
                }
    except Exception as e:
        logger.warning("TLS check failed for %s: %s", clean_host, e)
        return {
            "hostname": clean_host,
            "port": port,
            "error": str(e),
            "grade": "F",
            "verdict": "TLS Connection Failed",
            "chain_valid": False
        }
