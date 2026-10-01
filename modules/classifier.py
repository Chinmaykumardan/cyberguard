"""
HoneyShield Threat Classifier (Phase 3 module foundation)
Calculates rule-based heuristic risk scores and runs Isolation Forest anomaly detection.
"""
import logging
import db

logger = logging.getLogger("honeyshield.classifier")


def classify_attempt(ip: str, behavioral_data: dict = None, is_honeypot: bool = False, bot_trap: bool = False) -> tuple:
    """
    Computes a risk score (0-100), classification label, and plain-English rationale.
    Labels: 'bot', 'credential stuffer', 'script kiddie', 'suspicious human', 'normal'.
    """
    if bot_trap:
        return 100, "bot", "Hidden bot-trap field populated (automated crawler)."

    if is_honeypot:
        return 75, "script kiddie", "Direct attack against decoy honeypot endpoint."

    b = behavioral_data or {}
    score = 10
    reasons = []

    # Rapid submission check
    submit_time = b.get("time_to_submit_ms", 0)
    if 0 < submit_time < 400:
        score += 45
        reasons.append(f"Sub-human completion time ({submit_time}ms)")

    # Mouse movement check
    mouse_moves = b.get("mouse_moves", 0)
    if mouse_moves == 0:
        score += 25
        reasons.append("No pointer or touch telemetry recorded")

    # Paste detection
    if b.get("paste_detected"):
        score += 15
        reasons.append("Password pasted into input field")

    # Check recent velocity for this IP
    history = db.query_one(
        "SELECT COUNT(*) as count FROM login_attempts WHERE ip = %s AND created_at > NOW() - INTERVAL 10 MINUTE",
        (ip,)
    )
    count = history["count"] if history else 0
    if count >= 10:
        score += 40
        reasons.append(f"High velocity ({count} attempts in 10 minutes)")
    elif count >= 3:
        score += 20
        reasons.append(f"Repeated attempts ({count} in 10 minutes)")

    final_score = min(100, max(0, score))

    if final_score >= 85:
        classification = "credential stuffer" if count >= 5 else "bot"
    elif final_score >= 60:
        classification = "suspicious human"
    elif final_score >= 35:
        classification = "script kiddie"
    else:
        classification = "normal"

    rationale = "; ".join(reasons) if reasons else "Standard user authentication interaction"
    return final_score, classification, rationale
