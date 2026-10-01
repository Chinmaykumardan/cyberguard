"""
HoneyShield Phishing & Social Engineering Analyzer Module (Phase 4 foundation)
Extracts indicators, detects urgency cues, and identifies credential harvesting lures.
"""
import re
import logging

logger = logging.getLogger("honeyshield.phishing")

URGENCY_REGEX = re.compile(
    r"\b(urgent|immediately|action required|suspended|within 24 hours|account alert|final notice|unauthorized access)\b",
    re.IGNORECASE
)
CREDENTIAL_REGEX = re.compile(
    r"\b(password|sign in|login|verify your account|credentials|reset password|validate identity)\b",
    re.IGNORECASE
)
PAYMENT_REGEX = re.compile(
    r"\b(invoice|wire transfer|gift card|crypto|bitcoin|billing problem|payment overdue)\b",
    re.IGNORECASE
)
LINK_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


def analyze_phishing_content(content: str) -> dict:
    """Analyzes message body for social engineering lures, extracted links, and deception patterns."""
    text = content or ""
    urgency_matches = URGENCY_REGEX.findall(text)
    cred_matches = CREDENTIAL_REGEX.findall(text)
    payment_matches = PAYMENT_REGEX.findall(text)
    links = LINK_REGEX.findall(text)

    score = 0
    if urgency_matches:
        score += 30
    if cred_matches:
        score += 35
    if payment_matches:
        score += 20
    if links:
        score += 15

    risk_score = min(100, score)

    if risk_score >= 65:
        verdict = "Likely phishing"
    elif risk_score >= 35:
        verdict = "Review with caution"
    else:
        verdict = "Low-risk content"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "urgency_detected": bool(urgency_matches),
        "credential_request": bool(cred_matches),
        "payment_pressure": bool(payment_matches),
        "links": links[:10],
        "detail": f"{len(urgency_matches) + len(cred_matches) + len(payment_matches)} behavioral indicators flagged"
    }
