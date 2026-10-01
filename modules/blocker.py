"""
HoneyShield IP Blocker Module (Phase 3 foundation)
Maintains active IP blocks and firewall allowlists.
"""
import logging
from config import Config
import db

logger = logging.getLogger("honeyshield.blocker")


def is_ip_blocked(ip: str) -> bool:
    """Checks whether an IP address is actively blocked in the database."""
    if not ip or ip in Config.ALLOWLIST_IPS:
        return False
    row = db.query_one(
        "SELECT id FROM blocked_ips WHERE ip = %s AND is_active = 1 LIMIT 1",
        (ip,)
    )
    return bool(row)


def block_ip(ip: str, reason: str, risk_score: int = 100, user_id: int = None) -> bool:
    """Adds or updates an active block for the specified IP address."""
    if not ip or ip in Config.ALLOWLIST_IPS:
        logger.warning("Attempted to block allowlisted or invalid IP: %s", ip)
        return False
    try:
        db.execute(
            """
            INSERT INTO blocked_ips (ip, reason, risk_score, is_active, blocked_by_user_id)
            VALUES (%s, %s, %s, 1, %s)
            ON DUPLICATE KEY UPDATE
                reason = VALUES(reason),
                risk_score = VALUES(risk_score),
                is_active = 1,
                unblocked_at = NULL,
                blocked_by_user_id = VALUES(blocked_by_user_id)
            """,
            (ip, reason[:255], risk_score, user_id)
        )
        logger.info("IP %s blocked successfully: %s", ip, reason)
        return True
    except Exception as e:
        logger.error("Failed to block IP %s: %s", ip, e)
        return False


def unblock_ip(ip: str) -> bool:
    """Removes an IP address from active block enforcement."""
    if not ip:
        return False
    try:
        _, count = db.execute(
            "UPDATE blocked_ips SET is_active = 0, unblocked_at = NOW() WHERE ip = %s",
            (ip,)
        )
        logger.info("IP %s unblocked (rows affected: %s)", ip, count)
        return count > 0
    except Exception as e:
        logger.error("Failed to unblock IP %s: %s", ip, e)
        return False
