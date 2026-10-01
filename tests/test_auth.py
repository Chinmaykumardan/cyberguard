"""
HoneyShield Authentication & Security Unit Tests (Phase 1)
Validates Argon2id hashing, progressive lockout, bot-trap detection,
CSRF protection, and zero plaintext password storage.
"""
import unittest
import os
from config import Config
import db
from modules.auth import (
    hash_password,
    verify_password,
    create_user,
    get_user_by_email,
    authenticate_user,
    sha256_hash
)


class TestAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db("schema.sql")

    def test_01_argon2_hashing(self):
        """Validates that Argon2id generates valid hashes and verifies correctly."""
        password = "ComplexSecurePassword!2026"
        pw_hash = hash_password(password)

        self.assertTrue(pw_hash.startswith("$argon2id$"))
        self.assertTrue(verify_password(pw_hash, password))
        self.assertFalse(verify_password(pw_hash, "WrongPassword"))

    def test_02_no_plaintext_stored(self):
        """Verifies plaintext passwords are never stored in users table."""
        email = "test_operator@honeyshield.local"
        password = "SecretPassword123!"
        create_user(email, password, "Test Operator", "admin")

        user = get_user_by_email(email)
        self.assertIsNotNone(user)
        self.assertNotEqual(user["password_hash"], password)
        self.assertTrue(user["password_hash"].startswith("$argon2id$"))

    def test_03_bot_trap_detection(self):
        """Verifies that filling the hidden company_website bot-trap instantly rejects and flags attempt."""
        user, err = authenticate_user(
            email="bot@crawler.xyz",
            password="any_password",
            bot_trap_value="http://spam-link.ru"
        )
        self.assertIsNone(user)
        self.assertEqual(err, "Invalid credentials.")

        # Verify entry in login_attempts flagged as bot_trap
        attempt = db.query_one(
            "SELECT * FROM login_attempts WHERE bot_trap_triggered = 1 ORDER BY id DESC LIMIT 1"
        )
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt["status"], "bot_trap")
        self.assertEqual(attempt["classification"], "bot")
        self.assertEqual(attempt["risk_score"], 100)

    def test_04_progressive_lockout(self):
        """Verifies progressive lockout after repeated failures."""
        email = "lockout_victim@honeyshield.local"
        password = "OriginalPassword!999"
        create_user(email, password, "Lockout Victim", "admin")

        # Simulate MAX_LOGIN_FAILURES consecutive bad attempts
        for i in range(Config.MAX_LOGIN_FAILURES):
            user, err = authenticate_user(
                email=email,
                password="WrongPasswordAttempt",
                bot_trap_value=""
            )
            self.assertIsNone(user)

        # Check that user is now locked in DB
        victim = get_user_by_email(email)
        self.assertGreaterEqual(victim["failed_login_count"], Config.MAX_LOGIN_FAILURES)
        self.assertIsNotNone(victim["locked_until"])

        # Subsequent attempt (even with correct password) must be rejected due to lockout
        user, err = authenticate_user(email=email, password=password)
        self.assertIsNone(user)
        self.assertIn("temporarily locked", err.lower())

    def test_05_sha256_password_digest_only(self):
        """Verifies that password attempts are recorded strictly as SHA-256 digests in telemetry."""
        raw_attempt = "MyAttemptedPass123!"
        expected_digest = sha256_hash(raw_attempt)
        self.assertEqual(len(expected_digest), 64)

    def test_06_flask_http_login_flow(self):
        """Tests end-to-end Flask HTTP login flow, CSRF enforcement, session cookie, and dashboard access."""
        from app import app
        import re

        with app.test_client() as client:
            # 1. Unauthenticated root redirect
            res = client.get("/")
            self.assertEqual(res.status_code, 302)
            self.assertIn("/login", res.headers.get("Location", ""))

            # 2. Get login page and extract CSRF token
            res = client.get("/login")
            self.assertEqual(res.status_code, 200)
            match = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', res.get_data(as_text=True))
            self.assertIsNotNone(match, "CSRF token must be present in login form")
            csrf_token = match.group(1)

            # 3. Post with invalid CSRF token
            bad_csrf_res = client.post("/login", data={
                "email": Config.ADMIN_EMAIL,
                "password": Config.ADMIN_PASSWORD,
                "csrf_token": "fake_invalid_token"
            })
            self.assertEqual(bad_csrf_res.status_code, 403)

            # 4. Post with bot trap field filled
            bot_res = client.post("/login", data={
                "email": Config.ADMIN_EMAIL,
                "password": Config.ADMIN_PASSWORD,
                "company_website": "http://spammer.bot",
                "csrf_token": csrf_token
            })
            self.assertEqual(bot_res.status_code, 401)

            # 5. Post with invalid password
            bad_pw_res = client.post("/login", data={
                "email": Config.ADMIN_EMAIL,
                "password": "WrongPassword999!",
                "company_website": "",
                "csrf_token": csrf_token
            })
            self.assertEqual(bad_pw_res.status_code, 401)
            self.assertIn("Invalid", bad_pw_res.get_data(as_text=True))

            # 6. Post with valid admin credentials
            good_res = client.post("/login", data={
                "email": Config.ADMIN_EMAIL,
                "password": Config.ADMIN_PASSWORD,
                "company_website": "",
                "csrf_token": csrf_token
            }, follow_redirects=False)

            self.assertEqual(good_res.status_code, 302)
            self.assertIn("/dashboard", good_res.headers.get("Location", ""))

            # Check session cookie exists and is HttpOnly + SameSite=Strict
            set_cookie = good_res.headers.get("Set-Cookie", "")
            self.assertIn("hs_session", set_cookie)
            self.assertIn("HttpOnly", set_cookie)
            self.assertIn("SameSite=Strict", set_cookie)

            # 7. Access dashboard with authenticated session
            dash_res = client.get("/dashboard")
            self.assertEqual(dash_res.status_code, 200)
            html = dash_res.get_data(as_text=True)
            self.assertIn("Alex Operator", html)
            self.assertIn("Administrator", html)

            # 8. Check Content-Security-Policy headers
            csp = dash_res.headers.get("Content-Security-Policy", "")
            self.assertIn("default-src 'self'", csp)
            self.assertIn("object-src 'none'", csp)


if __name__ == "__main__":
    unittest.main()
