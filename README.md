# HoneyShield — Threat Intelligence & Security Operations Center

> **SECURITY & ETHICS NOTICE**  
> HoneyShield honeypot decoys, security auditing tools, and outbound URL/header scanners are designed **strictly** for systems and networks that you own or are explicitly authorized to test. Unauthorized penetration testing, port scanning, or vulnerability probing against external third-party infrastructure without permission is unethical and potentially illegal.

---

## Overview

**HoneyShield** is an AI-assisted threat intelligence console and Security Operations Center (SOC) designed to detect, track, classify, and mitigate authentication attacks before they compromise core services.

### Core Architectural Features (Phase 1)
- **Decoupled Frontend**: Clean Jinja2 template architecture (`templates/`) with strict Content-Security-Policy (no inline JavaScript, no inline CSS styles, zero `style=""` attributes).
- **ES Module Toolkit**: Modular JavaScript architecture under `static/js/` with safe DOM construction (`textContent` / `createElement`) preventing DOM-based XSS.
- **Enterprise MySQL 8 / MariaDB Data Layer**: 6 relational tables (`users`, `login_attempts`, `blocked_ips`, `alerts`, `url_scans`, `tool_usage_log`) with InnoDB engines, `utf8mb4` character set, foreign keys, timestamps, and composite `(ip, created_at)` indexes.
- **Thread-Safe Connection Pooling**: PyMySQL pooled via DBUtils (`PooledDB`) with parameterized queries preventing SQL injection across all operations.
- **Argon2id Authentication**: State-of-the-art password hashing using `argon2-cffi` with memory-hard parameters (64 MiB, 3 iterations, 4 parallelism). Plaintext passwords are never logged or stored.
- **Progressive Account & Network Lockout**: Progressive rate limiting and lockout enforcement (15-minute lockouts after 5 consecutive failures).
- **Honeypot Bot-Trap Protection**: Hidden `company_website` bot-trap form field that immediately detects and classifies automated crawlers with risk score 100.
- **Strict Session Controls**: Server-side signed session cookies with `HttpOnly`, `SameSite=Strict`, and `Secure` flags.
- **Comprehensive CSRF Protection**: Cryptographically random 32-byte CSRF token validation on all state-altering requests (`POST`, `PUT`, `DELETE`).

---

## Project Structure

```
├── app.py                      # Primary Flask application and route controllers
├── config.py                   # Centralized security settings and environment loader
├── db.py                       # Thread-safe PyMySQL PooledDB connection pool manager
├── schema.sql                  # MySQL 8 relational schema with constraints and indexes
├── create_admin.py             # Administrator bootstrapping script
├── simulate_attacks.py         # Local attack simulator (restricted to 127.0.0.1)
├── server.ts                   # Full-stack Node/Express reverse proxy bridge
├── requirements.txt            # Pinned Python package dependencies
├── package.json                # Web app dependencies and dev runner scripts
├── tsconfig.json               # TypeScript configuration
├── vite.config.ts              # Vite asset builder configuration
├── metadata.json               # AI Studio application metadata
├── .env.example                # Configuration blueprint template
├── .env                        # Active local environment variables
├── README.md                   # System documentation and operational runbook
├── modules/
│   ├── auth.py                 # Argon2id hashing, sessions, CSRF, lockout, bot-trap
│   ├── honeypot.py             # Decoy route handlers and delayed response engine
│   ├── classifier.py           # Risk scoring heuristics and behavioral telemetry
│   ├── blocker.py              # Firewall blocklist and allowlist enforcement
│   ├── alerts.py               # Incident notification pipeline and Telegram alerts
│   ├── ssrf.py                 # SSRF validation, private IP filter, DNS rebinding defense
│   ├── url_scanner.py          # SSRF-protected destination and anatomy scanner
│   ├── headers.py              # HTTP security response headers analyzer
│   ├── tls_checker.py          # SSL/TLS certificate metadata and expiration checker
│   └── phishing.py             # Social engineering and urgency indicator analyzer
├── templates/
│   ├── base.html               # Master layout with security headers and toast dialogs
│   ├── login.html              # Operator sign-in page with bot-trap & CSRF protection
│   └── dashboard.html          # Authenticated SOC dashboard & live telemetry views
├── static/
│   ├── css/
│   │   └── app.css             # Scoped stylesheet with @layer reset, base, components, utilities
│   └── js/
│       ├── app.js              # Main ES module controller
│       ├── login.js            # Login behavioral telemetry capture (typing, mouse, latency)
│       ├── dashboard.js        # Canvas chart engine, tab switcher, and telemetry refresh
│       ├── password-strength.js# Client-side entropy and crack-time analyzer
│       ├── generator.js        # Web Crypto password generator and clipboard manager
│       ├── url-scanner.js      # Safe URL inspection controller
│       ├── headers.js          # Security header report DOM builder
│       ├── tls.js              # TLS certificate inspector
│       └── phishing.js         # Phishing analysis and indicator parser
└── tests/
    └── test_auth.py            # Unit & HTTP integration test suite for Phase 1
```

---

## Setup & Running Instructions

### 1. Requirements
- Python 3.10+ (Python 3.11 / 3.12 recommended)
- MariaDB / MySQL 8.0+
- Node.js 18+ (for development proxy)

### 2. Database Initialization
Ensure MySQL/MariaDB service is running:
```bash
service mariadb start
mysql -u root -e "CREATE DATABASE IF NOT EXISTS honeyshield CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root honeyshield < schema.sql
```

### 3. Bootstrap Administrator
Create the primary security operator account:
```bash
python3 create_admin.py
```
*Default Credentials configured in `.env`:*
- **Email:** `admin@honeyshield.local`
- **Password:** `HoneyShield@Admin2026!Secure`
- **Operator Name:** `Alex Operator`

### 4. Running the Application

#### Option A: Running Directly with Python Flask
```bash
python3 app.py
```
*The application starts at `http://127.0.0.1:5000`.*

#### Option B: Running Full-Stack Dev Server (Port 3000)
```bash
npm run dev
```
*Listens on `http://0.0.0.0:3000` and automatically proxies to the Python Flask backend.*

### 5. Running the Automated Test Suite
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### 6. Simulating Local Attacks (Development Verification)
```bash
python3 simulate_attacks.py http://127.0.0.1:5000
```
*(Refuses execution on any target other than `127.0.0.1` or `localhost`)*

---

## Phase 1 Test Checklist

| Check | Test Description | Expected Result | Verified |
|---|---|---|---|
| **1.1** | Unauthenticated request to `/` or `/dashboard` | Redirects (`302`) to `/login` | ✅ Verified |
| **1.2** | Render `/login` GET route | Returns `200 OK` with valid CSRF token in hidden input | ✅ Verified |
| **1.3** | Submit `/login` with invalid CSRF token | Returns `403 Forbidden` ("CSRF validation failed") | ✅ Verified |
| **1.4** | Populate hidden bot-trap field `company_website` | Rejects with `401`, logs attempt as `bot_trap` with risk 100 | ✅ Verified |
| **1.5** | 5 consecutive failed logins for an account | Triggers progressive lockout (`15 minutes`) | ✅ Verified |
| **1.6** | Submit valid credentials (`admin@honeyshield.local`) | Returns `302 -> /dashboard`, sets HttpOnly `hs_session` cookie | ✅ Verified |
| **1.7** | Access `/dashboard` with authenticated session | Returns `200 OK`, renders logged-in user ("Alex Operator") | ✅ Verified |
| **1.8** | Verify database storage (`users` and `login_attempts`) | Only Argon2id hashes and SHA-256 digests stored; zero plaintext | ✅ Verified |
| **1.9** | Inspect response headers on all pages | Content-Security-Policy with zero inline scripts/styles present | ✅ Verified |
