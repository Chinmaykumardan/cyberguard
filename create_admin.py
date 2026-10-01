"""
HoneyShield Administrator Bootstrap Script
Provisions or updates the initial administrator account using settings from .env / Config.
Hashes the initial password with Argon2id and enforces active admin status.
"""
import sys
import logging
from config import Config
import db
from modules.auth import create_user, get_user_by_email

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("honeyshield.bootstrap")


def bootstrap_admin():
    """Initializes schema and seeds the primary operator administrator."""
    logger.info("Verifying database schema...")
    db.init_db("schema.sql")

    email = Config.ADMIN_EMAIL.strip().lower()
    password = Config.ADMIN_PASSWORD
    name = Config.ADMIN_NAME.strip()

    if not email or not password:
        logger.error("ADMIN_EMAIL or ADMIN_PASSWORD not configured in .env!")
        sys.exit(1)

    existing = get_user_by_email(email)
    if existing:
        logger.info("Admin user '%s' already exists (ID: %s). Updating credentials...", email, existing["id"])
    else:
        logger.info("Creating new administrator account for '%s'...", email)

    user_id = create_user(
        email=email,
        password=password,
        full_name=name,
        role="admin"
    )

    logger.info("=" * 60)
    logger.info("HoneyShield Admin Account Ready:")
    logger.info("  Email:    %s", email)
    logger.info("  Name:     %s", name)
    logger.info("  Role:     admin")
    logger.info("  User ID:  %s", user_id)
    logger.info("=" * 60)
    return user_id


if __name__ == "__main__":
    bootstrap_admin()
