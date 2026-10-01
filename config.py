"""
HoneyShield Configuration Module
Loads application configuration and security policies from environment variables.
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()


class Config:
    """Base application security and operational configuration."""
    
    # Environment
    ENV = os.getenv("FLASK_ENV", "production")
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    PORT = int(os.getenv("PORT", "5000"))
    
    # Cryptographic secret key for session signing and CSRF tokens
    SECRET_KEY = os.getenv("SECRET_KEY", "hs-dev-secret-key-change-in-production-32bytes")
    
    # Cookie security policy: strict session controls
    SESSION_COOKIE_HTTPONLY = True
    # Secure flag enabled in production or if behind HTTPS
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1", "yes") or (ENV == "production")
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_NAME = "hs_session"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Database Settings (MySQL 8 / MariaDB)
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "honeyshield")
    DB_POOL_MIN = int(os.getenv("DB_POOL_MIN", "2"))
    DB_POOL_MAX = int(os.getenv("DB_POOL_MAX", "20"))
    
    # Initial Administrator Provisioning
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@honeyshield.local")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "HoneyShield@Admin2026!Secure")
    ADMIN_NAME = os.getenv("ADMIN_NAME", "Alex Operator")
    
    # Rate Limiting & Account Lockout Policy
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "100 per minute")
    LOGIN_RATELIMIT_IP = os.getenv("LOGIN_RATELIMIT_IP", "10 per minute")
    LOGIN_RATELIMIT_ACCOUNT = os.getenv("LOGIN_RATELIMIT_ACCOUNT", "5 per minute")
    MAX_LOGIN_FAILURES = int(os.getenv("MAX_LOGIN_FAILURES", "5"))
    LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
    
    # Honeypot Bot Trap Field Name (hidden form field)
    BOT_TRAP_FIELD = os.getenv("BOT_TRAP_FIELD", "company_website")
    
    # Auto-blocking threshold & allowlist (Phase 3)
    BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "85"))
    ALLOWLIST_IPS = [
        ip.strip() for ip in os.getenv("ALLOWLIST_IPS", "127.0.0.1,::1").split(",") if ip.strip()
    ]
    
    # Optional Telegram Alerting (Phase 3)
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    
    # External Scanners (Phase 4)
    SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
    PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()
