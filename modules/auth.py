"""
HoneyShield Authentication & Session Security Module
Implements Argon2id password hashing, progressive account lockout,
CSRF token validation, honeypot bot-trap detection, and session security.
"""
import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps
import argon2
from flask import request, session, redirect, url_for, abort, g, has_request_context
from config import Config
import db

logger = logging.getLogger("honeyshield.auth")

# Argon2id password hasher with production-grade parameters
_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    type=argon2.Type.ID
)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id. Never stores or logs plaintext."""
    if not password:
        raise ValueError("Password cannot be empty.")
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verifies a password against an Argon2id hash."""
    if not stored_hash or not password:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
        return False
    except Exception as e:
        logger.error("Unexpected error during password verification: %s", e)
        return False


def sha256_hash(text: str) -> str:
    """Computes SHA-256 digest of input (used strictly for one-way pattern tracking of attempted passwords)."""
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Generates a cryptographically strong CSRF token and binds it to the user session."""
    if not has_request_context():
        return secrets.token_hex(32)
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf(token: str) -> bool:
    """Validates the provided CSRF token against the session token in constant time."""
    if not has_request_context():
        return True
    expected = session.get("csrf_token")
    if not expected or not token:
        return False
    return secrets.compare_digest(expected, token)


def check_csrf():
    """Flask pre-request hook to validate CSRF on unsafe HTTP methods."""
    if not has_request_context():
        return
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not validate_csrf(token):
            logger.warning(
                "CSRF validation failed for IP %s on route %s",
                get_client_ip(),
                request.path
            )
            abort(403, description="CSRF validation failed. Refresh the page and try again.")


def get_client_ip() -> str:
    """Extracts the client IP address safely, prioritizing X-Forwarded-For if trusted."""
    if not has_request_context():
        return "127.0.0.1"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        if client_ip:
            return client_ip
    return request.remote_addr or "127.0.0.1"


def get_user_by_email(email: str):
    """Retrieves an active user record by email using a parameterized query."""
    if not email:
        return None
    return db.query_one(
        "SELECT * FROM users WHERE email = %s LIMIT 1",
        (email.strip().lower(),)
    )


def get_user_by_id(user_id: int):
    """Retrieves an active user record by primary key."""
    if not user_id:
        return None
    return db.query_one(
        "SELECT * FROM users WHERE id = %s LIMIT 1",
        (user_id,)
    )


def create_user(email: str, password: str, full_name: str, role: str = "admin") -> int:
    """Creates a new user record with an Argon2id password hash."""
    clean_email = email.strip().lower()
    pw_hash = hash_password(password)
    user_id, _ = db.execute(
        """
        INSERT INTO users (email, password_hash, full_name, role, is_active)
        VALUES (%s, %s, %s, %s, 1)
        ON DUPLICATE KEY UPDATE
            password_hash = VALUES(password_hash),
            full_name = VALUES(full_name),
            role = VALUES(role),
            is_active = 1
        """,
        (clean_email, pw_hash, full_name.strip(), role)
    )
    logger.info("Provisioned user account for %s with role %s", clean_email, role)
    return user_id


def log_login_attempt(
    ip: str,
    username: str,
    password_attempt: str,
    route: str,
    status: str,
    is_honeypot: bool = False,
    bot_trap_triggered: bool = False,
    behavioral_data: dict = None,
    risk_score: int = 0,
    classification: str = "normal",
    rationale: str = None
):
    """
    Records an authentication attempt in login_attempts.
    Plaintext password is NEVER stored or logged; only a one-way SHA-256 digest is kept.
    """
    b_data = behavioral_data or {}
    pw_sha = sha256_hash(password_attempt) if password_attempt else None
    user_agent = (request.headers.get("User-Agent", "") if has_request_context() else "Internal/1.0")[:500]
    safe_username = (username or "")[:255]

    try:
        db.execute(
            """
            INSERT INTO login_attempts (
                ip, username, password_hash_sha256, user_agent, route,
                status, is_honeypot, bot_trap_triggered,
                typing_speed_wpm, mouse_moves, paste_detected, time_to_submit_ms,
                risk_score, classification, rationale
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s
            )
            """,
            (
                ip,
                safe_username,
                pw_sha,
                user_agent,
                route,
                status,
                1 if is_honeypot else 0,
                1 if bot_trap_triggered else 0,
                b_data.get("typing_speed_wpm"),
                b_data.get("mouse_moves", 0),
                1 if b_data.get("paste_detected") else 0,
                b_data.get("time_to_submit_ms", 0),
                risk_score,
                classification,
                rationale
            )
        )
    except Exception as e:
        logger.error("Failed to log login attempt: %s", e)


def authenticate_user(email: str, password: str, bot_trap_value: str = "", behavioral_data: dict = None):
    """
    Authenticates an operator with progressive lockout and bot-trap honeypot defenses.
    Returns: (user_dict or None, error_message or None)
    """
    ip = get_client_ip()
    route = request.path if has_request_context() else "/login"
    clean_email = (email or "").strip().lower()

    # 1. BOT TRAP CHECK: If hidden bot-trap field is populated, instantly flag and reject!
    if bot_trap_value and bot_trap_value.strip():
        logger.warning("Bot trap triggered by IP %s (value='%s')", ip, bot_trap_value[:50])
        log_login_attempt(
            ip=ip,
            username=clean_email,
            password_attempt=password,
            route=route,
            status="bot_trap",
            is_honeypot=False,
            bot_trap_triggered=True,
            behavioral_data=behavioral_data,
            risk_score=100,
            classification="bot",
            rationale="Hidden bot-trap field company_website was populated."
        )
        return None, "Invalid credentials."

    if not clean_email or not password:
        return None, "Email and password are required."

    user = get_user_by_email(clean_email)

    # 2. CHECK PROGRESSIVE LOCKOUT
    now = datetime.now()
    if user and user.get("locked_until"):
        locked_until = user["locked_until"]
        if isinstance(locked_until, str):
            try:
                locked_until = datetime.fromisoformat(locked_until)
            except Exception:
                pass
        if locked_until and locked_until > now:
            remaining_mins = max(1, int((locked_until - now).total_seconds() / 60))
            log_login_attempt(
                ip=ip,
                username=clean_email,
                password_attempt=password,
                route=route,
                status="blocked",
                is_honeypot=False,
                behavioral_data=behavioral_data,
                risk_score=85,
                classification="credential stuffer",
                rationale="Attempt against locked account."
            )
            return None, f"Account is temporarily locked. Please try again in {remaining_mins} minutes."

    # Check recent failed attempts from this IP to prevent brute-force attacks across accounts
    recent_ip_failures = db.query_one(
        """
        SELECT COUNT(*) as count FROM login_attempts
        WHERE ip = %s AND status = 'failed' AND created_at > NOW() - INTERVAL %s MINUTE
        """,
        (ip, Config.LOCKOUT_MINUTES)
    )
    if recent_ip_failures and recent_ip_failures["count"] >= Config.MAX_LOGIN_FAILURES * 3:
        return None, "Too many failed attempts from your network. Please wait before retrying."

    # 3. VERIFY CREDENTIALS
    if not user or not user.get("is_active"):
        log_login_attempt(
            ip=ip,
            username=clean_email,
            password_attempt=password,
            route=route,
            status="failed",
            is_honeypot=False,
            behavioral_data=behavioral_data,
            risk_score=40,
            classification="suspicious human",
            rationale="Non-existent or disabled account requested."
        )
        return None, "Invalid username or password."

    is_valid = verify_password(user["password_hash"], password)

    if not is_valid:
        # Increment failure count
        new_fail_count = user["failed_login_count"] + 1
        lockout_time = None
        error_msg = "Invalid username or password."

        if new_fail_count >= Config.MAX_LOGIN_FAILURES:
            lockout_time = now + timedelta(minutes=Config.LOCKOUT_MINUTES)
            error_msg = f"Account locked for {Config.LOCKOUT_MINUTES} minutes due to repeated failed logins."
            db.execute(
                """
                UPDATE users
                SET failed_login_count = %s, locked_until = %s
                WHERE id = %s
                """,
                (new_fail_count, lockout_time, user["id"])
            )
        else:
            db.execute(
                """
                UPDATE users
                SET failed_login_count = %s
                WHERE id = %s
                """,
                (new_fail_count, user["id"])
            )

        log_login_attempt(
            ip=ip,
            username=clean_email,
            password_attempt=password,
            route=route,
            status="failed",
            is_honeypot=False,
            behavioral_data=behavioral_data,
            risk_score=50 + min(50, new_fail_count * 10),
            classification="credential stuffer" if new_fail_count >= 3 else "normal",
            rationale=f"Failed password attempt ({new_fail_count}/{Config.MAX_LOGIN_FAILURES})"
        )
        return None, error_msg

    # 4. SUCCESS: Reset lockout counters and record successful login
    db.execute(
        """
        UPDATE users
        SET failed_login_count = 0, locked_until = NULL, last_login_at = NOW()
        WHERE id = %s
        """,
        (user["id"],)
    )

    log_login_attempt(
        ip=ip,
        username=clean_email,
        password_attempt=password,
        route=route,
        status="success",
        is_honeypot=False,
        behavioral_data=behavioral_data,
        risk_score=5,
        classification="normal",
        rationale="Successful authenticated operator login."
    )

    return user, None


def login_user(user: dict):
    """Establishes an authenticated session for the given operator."""
    session.clear()
    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session["role"] = user["role"]
    session["full_name"] = user["full_name"]
    session["logged_in_at"] = datetime.now().isoformat()
    session.permanent = True
    # Generate fresh CSRF token for the new session
    generate_csrf_token()


def logout_user():
    """Destroys the current user session securely."""
    session.clear()


def get_current_user():
    """Retrieves the current authenticated user object or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_user_by_id(user_id)
    if not user or not user.get("is_active"):
        logout_user()
        return None
    # Add display initials for avatar
    parts = (user["full_name"] or user["email"]).strip().split()
    if len(parts) >= 2:
        user["initials"] = (parts[0][0] + parts[1][0]).upper()
    elif len(parts) == 1 and parts[0]:
        user["initials"] = parts[0][:2].upper()
    else:
        user["initials"] = "OP"
    return user


def login_required(admin_only: bool = True):
    """Decorator requiring an active authenticated session (and optionally admin role)."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.is_json or request.path.startswith("/api/"):
                    return {"error": "Authentication required"}, 401
                return redirect(url_for("login_route", next=request.path))
            if admin_only and user.get("role") != "admin":
                if request.is_json or request.path.startswith("/api/"):
                    return {"error": "Administrator privilege required"}, 403
                abort(403)
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator
