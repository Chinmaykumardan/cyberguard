"""
HoneyShield Alerts & Incident Feed Module (Phase 3 foundation)
Creates, persists, and delivers threat notifications to the security console and Telegram.
"""
import logging
import requests
from config import Config
import db

logger = logging.getLogger("honeyshield.alerts")


def create_alert(title: str, description: str, severity: str = "medium", ip: str = None, risk_score: int = 50) -> int:
    """Inserts a new threat notification into the alerts table and dispatches external alerts if configured."""
    try:
        alert_id, _ = db.execute(
            """
            INSERT INTO alerts (ip, severity, title, description, risk_score, is_reviewed)
            VALUES (%s, %s, %s, %s, %s, 0)
            """,
            (ip, severity, title[:255], description, risk_score)
        )
        logger.info("Security Alert [%s]: %s (ID: %s)", severity.upper(), title, alert_id)

        # Dispatch Telegram notification if configured
        if Config.TELEGRAM_BOT_TOKEN and Config.TELEGRAM_CHAT_ID:
            send_telegram_alert(title, description, severity, ip, risk_score)

        return alert_id
    except Exception as e:
        logger.error("Failed to create alert: %s", e)
        return -1


def send_telegram_alert(title: str, description: str, severity: str, ip: str, risk_score: int):
    """Sends formatted alert to configured Telegram chat."""
    try:
        text = (
            f"🛡️ *HoneyShield Alert* [{severity.upper()}]\n"
            f"*Title:* {title}\n"
            f"*Source IP:* `{ip or 'N/A'}`\n"
            f"*Risk Score:* {risk_score}/100\n"
            f"*Details:* {description}"
        )
        url = f"https://api.telegram.org/bot{Config.TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": Config.TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"}, timeout=4)
    except Exception as e:
        logger.warning("Telegram notification failed: %s", e)
