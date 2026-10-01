"""
HoneyShield Honeypot Engine (Phase 2 module foundation)
Handles decoy authentication endpoints, timing delays, and reconnaissance logging.
"""
import time
import random
import logging
from modules.auth import log_login_attempt

logger = logging.getLogger("honeyshield.honeypot")

DECOY_ROUTES = ["/wp-login", "/admin-login", "/phpmyadmin", "/wp-admin", "/xmlrpc.php"]


def handle_decoy_attempt(route: str, ip: str, username: str, password_attempt: str):
    """
    Handles a request to a decoy honeypot endpoint.
    Sleeps between 0.3s and 1.0s to simulate backend processing before returning failure.
    Logs full telemetry to login_attempts with SHA-256 password hash.
    """
    delay = random.uniform(0.3, 1.0)
    time.sleep(delay)

    log_login_attempt(
        ip=ip,
        username=username,
        password_attempt=password_attempt,
        route=route,
        status="failed",
        is_honeypot=True,
        bot_trap_triggered=False,
        risk_score=75,
        classification="script kiddie",
        rationale=f"Reconnaissance attempt against decoy honeypot endpoint '{route}'"
    )
    return {"error": "Invalid username or password"}, 401
