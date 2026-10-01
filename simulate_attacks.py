#!/usr/bin/env python3
"""
HoneyShield Security Simulation Tool
Simulates various attack patterns (credential stuffing, bot probes, decoy honeypot hits)
strictly against local http://127.0.0.1 for development and testing.

SAFETY RESTRICTION:
Refuses execution against any target other than 127.0.0.1 or localhost.
"""
import sys
import time
import random
from urllib.parse import urlparse
import requests

ALLOWED_TARGET_HOSTS = ("127.0.0.1", "localhost")


def check_target(target_url: str):
    """Enforces that simulate_attacks ONLY targets 127.0.0.1 / localhost."""
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in ALLOWED_TARGET_HOSTS:
        print(f"[SECURITY REFUSAL] HoneyShield simulation is strictly restricted to local development.")
        print(f"Target '{target_url}' (host '{hostname}') is forbidden.")
        sys.exit(1)


def simulate_honeypot_probes(base_url: str):
    """Probes decoy endpoints (/wp-login, /admin-login, /phpmyadmin)."""
    check_target(base_url)
    decoy_paths = ["/wp-login", "/admin-login", "/phpmyadmin"]
    print(f"\n[+] Simulating honeypot decoy scans on {base_url}...")

    for path in decoy_paths:
        url = f"{base_url.rstrip('/')}{path}"
        payload = {"email": "admin", "password": f"test_{random.randint(1000, 9999)}"}
        try:
            start = time.time()
            resp = requests.post(url, json=payload, timeout=5)
            elapsed = time.time() - start
            print(f"    --> Decoy probe {path} | Status: {resp.status_code} | Delay: {elapsed:.2f}s")
        except Exception as e:
            print(f"    [!] Error contacting {path}: {e}")
        time.sleep(0.4)


def simulate_credential_stuffing(base_url: str, attempts: int = 5):
    """Simulates rapid credential attempts from automated script."""
    check_target(base_url)
    url = f"{base_url.rstrip('/')}/api/login"
    usernames = ["root", "admin", "operator", "sysadmin", "deploy"]
    print(f"\n[+] Simulating credential stuffing velocity ({attempts} attempts) on {url}...")

    for i in range(attempts):
        user = usernames[i % len(usernames)]
        payload = {
            "email": f"{user}@example.local",
            "password": "wrongpassword123!",
            "company_website": "",  # normal
            "typing_speed_wpm": 250,  # inhuman speed
            "mouse_moves": 0,         # no mouse movement
            "paste_detected": True,
            "time_to_submit_ms": 120  # automated timing
        }
        try:
            resp = requests.post(url, json=payload, timeout=5)
            print(f"    Attempt {i+1}/{attempts} for '{user}' | Status: {resp.status_code}")
        except Exception as e:
            print(f"    [!] Error: {e}")
        time.sleep(0.2)


def simulate_bot_trap(base_url: str):
    """Simulates a dumb bot filling out the hidden bot-trap honeypot field."""
    check_target(base_url)
    url = f"{base_url.rstrip('/')}/api/login"
    print(f"\n[+] Simulating bot-trap honeypot field trigger on {url}...")
    payload = {
        "email": "crawler_bot@automated-scan.com",
        "password": "random_password_xyz",
        "company_website": "http://spammer-seo-link.com",  # BOT TRAP FILLED!
        "typing_speed_wpm": 0,
        "mouse_moves": 0,
        "time_to_submit_ms": 50
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        print(f"    Bot-trap submission | Status: {resp.status_code} | Response: {resp.text[:100]}")
    except Exception as e:
        print(f"    [!] Error: {e}")


def main():
    target = "http://127.0.0.1:5000"
    if len(sys.argv) > 1:
        target = sys.argv[1]

    check_target(target)
    print("=" * 65)
    print(f"HoneyShield Local Attack Simulator")
    print(f"Target: {target} (Local verification only)")
    print("=" * 65)

    simulate_honeypot_probes(target)
    simulate_bot_trap(target)
    simulate_credential_stuffing(target, attempts=4)
    print("\n[✓] Simulation completed successfully.")


if __name__ == "__main__":
    main()
