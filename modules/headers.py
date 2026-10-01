"""
HoneyShield HTTP Security Headers Analyzer Module (Phase 4 foundation)
Evaluates HTTP response headers and produces security grades with remediation guidance.
"""
import logging

logger = logging.getLogger("honeyshield.headers")


def analyze_header_text(raw_headers: str) -> dict:
    """Analyzes raw HTTP response headers pasted into the security operations console."""
    text = (raw_headers or "").lower()
    checks = [
        {"name": "Content-Security-Policy", "passed": "content-security-policy" in text, "rec": "Add strict CSP restricting script-src and object-src."},
        {"name": "Strict-Transport-Security", "passed": "strict-transport-security" in text, "rec": "Add HSTS header with max-age=31536000 and includeSubDomains."},
        {"name": "Clickjacking protection (X-Frame-Options)", "passed": "x-frame-options" in text or "frame-ancestors" in text, "rec": "Set X-Frame-Options: DENY or SAMEORIGIN."},
        {"name": "MIME sniffing defense (X-Content-Type-Options)", "passed": "x-content-type-options" in text, "rec": "Set X-Content-Type-Options: nosniff."},
        {"name": "Referrer-Policy", "passed": "referrer-policy" in text, "rec": "Set Referrer-Policy: strict-origin-when-cross-origin."},
        {"name": "Permissions-Policy", "passed": "permissions-policy" in text, "rec": "Disable unused browser APIs (camera, microphone, geolocation)."},
    ]

    passed_count = sum(1 for c in checks if c["passed"])
    score = int((passed_count / len(checks)) * 100)

    if score >= 80:
        verdict = "Strong baseline coverage"
        detail = f"{passed_count} of {len(checks)} recommended headers configured"
    elif score >= 50:
        verdict = "Headers need improvement"
        detail = f"{passed_count} of {len(checks)} headers present; harden missing defenses"
    else:
        verdict = "Critical headers missing"
        detail = f"Only {passed_count} of {len(checks)} headers found"

    return {
        "score": score,
        "verdict": verdict,
        "detail": detail,
        "checks": checks
    }
