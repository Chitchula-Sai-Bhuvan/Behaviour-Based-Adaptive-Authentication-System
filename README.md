# Behaviour-Based Adaptive Authentication System

### MFA Fatigue Detection & Risk-Based Access Control — Complete Study Guide

---

## Table of Contents

1. [What This Project Is](#1-what-this-project-is)
2. [Tech Stack — Every Tool and Why](#2-tech-stack--every-tool-and-why)
3. [Project Structure — Every File and Its Purpose](#3-project-structure--every-file-and-its-purpose)
4. [System Architecture](#4-system-architecture)
5. [Core Layer: `app/core/` — Configuration and Infrastructure](#5-core-layer-appcore--configuration-and-infrastructure)
6. [Database Layer: `app/db/` and `app/models/`](#6-database-layer-appdb-and-appmodels)
7. [Service Layer: `app/services/` — Business Logic](#7-service-layer-appservices--business-logic)
8. [API Layer: `app/api/` — Endpoints](#8-api-layer-appapi--endpoints)
9. [The 7-Signal Risk Engine — How Detection Works](#9-the-7-signal-risk-engine--how-detection-works)
10. [The Tamper-Evident Audit Chain](#10-the-tamper-evident-audit-chain)
11. [JWT Authentication & Token Lifecycle](#11-jwt-authentication--token-lifecycle)
12. [All UIs — Swagger, ReDoc, Browser Pages](#12-all-uis--swagger-redoc-browser-pages)
13. [Database Schema (v2)](#13-database-schema-v2)
14. [API Endpoints — Complete Reference](#14-api-endpoints--complete-reference)
15. [Security Features Summary](#15-security-features-summary)
16. [Environment Variables](#16-environment-variables)
17. [Installation & Setup](#17-installation--setup)
18. [Running the Application](#18-running-the-application)
19. [Test Scripts — What They Cover](#19-test-scripts--what-they-cover)
20. [Data Flow: Login to Risk Decision](#20-data-flow-login-to-risk-decision)
21. [Bugs Found and Fixed During Testing](#21-bugs-found-and-fixed-during-testing)

---

## 1. What This Project Is

This project implements a **behaviour-based adaptive authentication system** that detects and responds to **MFA fatigue attacks** in real time.

### What is an MFA Fatigue Attack?

An MFA fatigue attack occurs when an attacker who has stolen a user's password repeatedly sends MFA push notifications, hoping the user will eventually approve one out of confusion or frustration. Real-world examples include the **2022 Uber breach** (Lapsus$ group) and **2022 Cisco breach**.

### How This System Responds

The system monitors authentication event patterns, scores the risk of each session using 7 behavioural signals, and applies one of three access decisions:

| Decision   | Risk Score | Meaning                                    |
|------------|------------|--------------------------------------------|
| **ALLOW**  | 0 – 39     | Normal behaviour — grant access             |
| **VERIFY** | 40 – 69    | Suspicious — require step-up verification   |
| **BLOCK**  | 70+        | High risk — deny access                     |

---

## 2. Tech Stack — Every Tool and Why

### Backend

| Tool / Library       | Version    | Why This Was Chosen                                                                                                 |
|----------------------|------------|---------------------------------------------------------------------------------------------------------------------|
| **Python**           | 3.11+      | Primary language. Type hints enable auto-documentation. Tested on 3.14.                                             |
| **FastAPI**          | >= 0.115   | Modern async web framework. Auto-generates Swagger/OpenAPI docs from type hints. Built-in dependency injection (`Depends(get_db)`). Fastest pure-Python framework. |
| **Uvicorn**          | >= 0.30    | ASGI server that runs FastAPI. Production-grade performance. `--reload` flag for hot-reload during development.      |
| **SQLAlchemy 2.0**   | >= 2.0.30  | Python's most mature ORM. `Mapped[]` type hints, relationship management, transaction control. Supports any SQL DB.  |
| **PyMySQL**          | >= 1.1     | Pure-Python MySQL driver. No C compilation required (unlike `mysqlclient`), works on Windows/Mac/Linux without extra setup. |
| **Redis (redis-py)** | >= 5.0     | In-memory key-value store. Used for real-time counters (MFA request count, login attempt count) — orders of magnitude faster than SQL `COUNT()` queries. System works without it (graceful fallback to MySQL). |
| **bcrypt**           | >= 4.1     | Password hashing. Intentionally slow (~100ms per hash) making brute-force attacks impractical. OWASP recommended.   |
| **python-jose**      | >= 3.3     | JWT (JSON Web Token) library. Creates signed access tokens and refresh tokens with `HS256` (HMAC-SHA256).           |
| **SlowAPI**          | >= 0.1.9   | Rate limiting for FastAPI. Decorates endpoints with `@limiter.limit("10/minute")`. Tracks counters per-IP. Built on the `limits` library. |
| **Pydantic v2**      | >= 2.10    | Data validation. All API request/response bodies are Pydantic models. Rejects malformed input automatically with 422 errors. |
| **pydantic-settings** | >= 2.5    | Reads `.env` files and maps values to typed Python settings object. One `Settings` class = single source of truth.  |
| **Jinja2**           | >= 3.1     | HTML template engine. FastAPI's `templates.TemplateResponse()` renders the 4 browser pages.                          |
| **python-dotenv**    | >= 1.0     | Loads `.env` file into the environment. Used internally by pydantic-settings.                                        |
| **httpx**            | >= 0.27    | HTTP client used in test scripts. Supports connection pooling, timeouts, and base_url.                               |
| **cryptography**     | >= 42.0    | Required by PyMySQL for encrypted MySQL connections and by python-jose for JWT signing.                               |
| **secure**           | >= 0.3     | HTTP security headers helper (referenced but headers are also applied manually in middleware for full control).        |

### Frontend (No Build Step)

| Tool            | Why                                                                                       |
|-----------------|-------------------------------------------------------------------------------------------|
| **Tailwind CSS** (CDN) | Utility-first CSS framework. Styled via CDN `<script>` — no npm, no webpack, no build pipeline needed. |
| **Vanilla JavaScript** | Handles API calls (`fetch()`), form submission, and dashboard data loading. No React/Vue dependency. |

### Database

| Tool          | Why                                                                                          |
|---------------|----------------------------------------------------------------------------------------------|
| **MySQL 8.0+** | Relational database with ACID transactions. Needed for consistent audit logging, token revocation tracking, and referential integrity (foreign keys). |

### Optional Infrastructure

| Tool      | Why                                                                                              |
|-----------|--------------------------------------------------------------------------------------------------|
| **Redis** | Hot cache for signal counters (signals 1-3). If Redis is down, the system falls back to MySQL `COUNT()` queries automatically. The 30-second backoff cache in `redis_client.py` avoids a 0.5s timeout penalty on every API call when Redis is unavailable. |

---

## 3. Project Structure — Every File and Its Purpose

```
cloud_project_07/
|
|-- .env                          # Local secrets (DB password, JWT key) — not in git
|-- .env.example                  # Template showing what .env needs
|-- requirements.txt              # All Python dependencies
|-- README.md                     # This file — complete project guide
|-- SETUP.md                      # Step-by-step installation instructions
|-- TESTING.md                    # Test scenario descriptions
|
|-- app/
|   |-- __init__.py               # Makes app/ a Python package
|   |-- main.py                   # FastAPI entry point, middleware, router mounting
|   |
|   |-- core/                     # Configuration and infrastructure
|   |   |-- __init__.py
|   |   |-- config.py             # All settings from .env in one typed class
|   |   |-- limiter.py            # SlowAPI rate limiter instance
|   |   |-- logger.py             # Structured JSON logging setup
|   |   |-- redis_client.py       # Redis connection pool + graceful fallback
|   |   |-- security.py           # JWT create/decode, bcrypt hash, device fingerprint
|   |
|   |-- db/                       # Database connection
|   |   |-- __init__.py
|   |   |-- base.py               # SQLAlchemy DeclarativeBase (all models inherit this)
|   |   |-- session.py            # Engine, SessionLocal factory, get_db() dependency
|   |
|   |-- models/                   # ORM models = database tables (7 tables)
|   |   |-- __init__.py           # Imports all models so create_all() discovers them
|   |   |-- user.py               # users table
|   |   |-- auth_event.py         # auth_events table (audit log)
|   |   |-- mfa_challenge.py      # mfa_challenges table
|   |   |-- login_session.py      # login_sessions table
|   |   |-- risk_decision.py      # risk_decisions table
|   |   |-- trusted_device.py     # trusted_devices table
|   |   |-- revoked_token.py      # revoked_tokens table
|   |
|   |-- services/                 # Business logic (8 services)
|   |   |-- __init__.py
|   |   |-- auth_service.py       # Register, authenticate, password policy, token revoke
|   |   |-- mfa_service.py        # Challenge create/consume, replay prevention
|   |   |-- behaviour_monitor.py  # 7-signal detection engine (core of the project)
|   |   |-- risk_engine.py        # Weighted scoring + ALLOW/VERIFY/BLOCK decisions
|   |   |-- decision_controller.py# Orchestrates monitor -> engine pipeline
|   |   |-- audit_logger.py       # Tamper-evident hash chain for auth_events
|   |   |-- session_service.py    # Create, validate, touch, terminate sessions
|   |   |-- device_service.py     # Register and look up trusted devices
|   |
|   |-- api/                      # HTTP endpoints (5 routers)
|   |   |-- __init__.py
|   |   |-- schemas.py            # Pydantic request/response models (separate from ORM)
|   |   |-- auth.py               # /api/register, /api/login, /api/logout, /api/refresh
|   |   |-- mfa.py                # /api/mfa/request, /api/mfa/respond
|   |   |-- risk.py               # /api/risk/evaluate, /api/risk/audit
|   |   |-- logs.py               # /api/logs/events, decisions, devices, sessions
|   |   |-- pages.py              # HTML page routes (/, /register, /mfa, /dashboard)
|   |
|   |-- templates/                # Browser UI (Jinja2 HTML)
|       |-- login.html            # Login form
|       |-- register.html         # Registration form with password hints
|       |-- mfa.html              # MFA approve/deny screen
|       |-- dashboard.html        # Security monitoring dashboard
|
|-- tests/
    |-- simulate_attacks.py       # 3 attack scenario simulation
    |-- test_edge_cases.py        # 37 security edge-case tests
```

---

## 4. System Architecture

```
   Browser (UI)  or  Test Script (httpx)
          |
          | HTTP requests
          v
  +---------------------------------------------------+
  |            FastAPI Application (main.py)           |
  |                                                     |
  |  Middleware Stack (applied to every request):        |
  |    1. Security Headers (CSP, X-Frame, nosniff...)   |
  |    2. CORS Policy (allowed origins from .env)       |
  |    3. Rate Limiter (SlowAPI, per-IP buckets)        |
  |                                                     |
  |  API Routers:                                       |
  |    auth.py   mfa.py   risk.py   logs.py   pages.py |
  |       |         |        |         |         |      |
  |       v         v        v         v         |      |
  |  +------------------------------------------+|      |
  |  |         Services Layer                    ||      |
  |  |  auth_service    mfa_service              ||      |
  |  |  behaviour_monitor  risk_engine           ||      |
  |  |  decision_controller  audit_logger        ||      |
  |  |  session_service  device_service          ||      |
  |  +--------------------+---------------------+|      |
  +------------------------|----------------------+      |
                           |                             |
              +------------+-------------+               |
              |                          |               |
              v                          v               v
  +-------------------+    +----------+    +------------------+
  |    MySQL Database  |    |  Redis   |    | Jinja2 Templates |
  |  7 tables:         |    | (optional)|    | 4 HTML pages     |
  |  users             |    | counters |    | login, register, |
  |  auth_events       |    | for fast |    | mfa, dashboard   |
  |  mfa_challenges    |    | signal   |    +------------------+
  |  login_sessions    |    | checks   |
  |  risk_decisions    |    +----------+
  |  trusted_devices   |
  |  revoked_tokens    |
  +-------------------+
```

---

## 5. Core Layer: `app/core/` — Configuration and Infrastructure

### `config.py` — Centralised Settings

Every configurable value lives here in a single `Settings` class. Uses **pydantic-settings** which:
- Automatically reads from `.env` file
- Validates types (int stays int, bool stays bool)
- Provides defaults so the app works out of the box for local dev

Key setting groups:
- **Database**: host, port, name, user, password
- **Redis**: host, port, db number, password
- **JWT**: secret key, algorithm, token lifetimes
- **Account Lockout**: max failed logins (5), lockout duration (15 min)
- **Password Policy**: min length (8), require uppercase/digit/special
- **MFA**: challenge TTL (5 min), max active challenges (3)
- **Behaviour Windows**: how far back to look for each signal (2-5 min)
- **Risk Weights**: how many points each signal adds (10-40 per signal)
- **Decision Thresholds**: cutoff for ALLOW (39), VERIFY (69), BLOCK (70+)
- **Rate Limits**: login (10/min), register (5/min), MFA (20/min)

### `security.py` — Cryptographic Utilities

Three responsibilities:

1. **Password hashing**: `hash_password()` and `verify_password()` using **bcrypt**
   - bcrypt generates a random salt per password
   - Work factor makes each hash take ~100ms (intentionally slow to resist brute force)

2. **JWT tokens**: `create_access_token()`, `create_refresh_token()`, `decode_token()`
   - Access token: short-lived (30 min), carries `user_id`, `username`, `jti` (unique ID)
   - Refresh token: long-lived (7 days), carries a `type: "refresh"` claim
   - Both signed with `HS256` using the `SECRET_KEY` from `.env`

3. **Device fingerprinting**: `compute_device_fingerprint(ip, user_agent, accept_language)`
   - SHA-256 hash of `IP|User-Agent|Accept-Language`
   - Creates a stable identifier for each device without tracking cookies

### `limiter.py` — Rate Limiting

Creates a **SlowAPI** `Limiter` instance. The key function `_client_ip()`:
1. Checks `X-Forwarded-For` header first (for reverse proxy / test isolation)
2. Falls back to `request.client.host` (raw TCP peer address)
3. Defaults to `127.0.0.1` if neither is available

This ensures:
- Each IP gets its own rate-limit bucket
- Tests can use fake IPs via X-Forwarded-For to avoid bucket collisions
- Works behind nginx/HAProxy in production

### `redis_client.py` — Redis with Graceful Fallback

The design principle: **Redis is optional**. If Redis is down, the app still works.

Key features:
- Connection pool (reuses TCP connections instead of opening a new one per request)
- 30-second **backoff cache**: after a failed connection, it skips Redis for 30 seconds instead of attempting (and failing) on every API call
- Socket timeout reduced to 0.5 seconds (so a dead Redis doesn't slow down requests)
- `RedisCounters` class provides `increment()` and `get_count()` for signal detection

### `logger.py` — Structured JSON Logging

Outputs logs as JSON objects like:
```json
{"timestamp": "2026-03-08T...", "level": "INFO", "logger": "app.services.auth_service", "message": "Login success", "user_id": 5, "ip": "127.0.0.1"}
```

JSON logs are machine-parseable — essential for production log aggregation tools (ELK Stack, AWS CloudWatch, Datadog).

---

## 6. Database Layer: `app/db/` and `app/models/`

### `app/db/base.py`

Contains the SQLAlchemy `DeclarativeBase`. Every ORM model class inherits from `Base`. This is standard SQLAlchemy 2.0 pattern.

### `app/db/session.py`

- Creates the `Engine` (database connection) from the `DATABASE_URL` in settings
- Creates `SessionLocal` factory (produces database sessions)
- Defines `get_db()` — a FastAPI dependency that yields a DB session per request and auto-closes it

### The 7 Database Tables (ORM Models)

| Model File | Table Name | What It Stores | Why It Exists |
|------------|------------|----------------|---------------|
| `user.py` | `users` | username, bcrypt password_hash, failed_login_attempts, locked_until, last_login_at, last_login_ip | Core user identity. `failed_login_attempts` and `locked_until` enable account lockout. `last_login_ip` enables IP-change detection. |
| `auth_event.py` | `auth_events` | event_id, user_id, event_type (LOGIN/MFA_REQUEST/APPROVE/DENY/LOGOUT/LOCKOUT), ip_address, device_info, device_fingerprint, session_id, success, chain_hash, timestamp | **Append-only audit log.** Every authentication action is recorded. The `chain_hash` field creates a tamper-evident linked chain. The behaviour monitor queries this table to count events within time windows. |
| `mfa_challenge.py` | `mfa_challenges` | challenge_id (UUID), user_id, expires_at, used (boolean) | Stores pending MFA challenges. The `used` flag prevents **replay attacks** (same challenge can't be approved twice). `expires_at` enforces a 5-minute TTL. |
| `login_session.py` | `login_sessions` | session_id (UUID), user_id, ip_address, created_at, last_active_at, expires_at, is_active, terminated_reason | Tracks active login sessions. Sessions can be terminated on logout or by the system. `last_active_at` is updated on each request ("session touch"). |
| `risk_decision.py` | `risk_decisions` | decision_id, user_id, risk_score, decision (ALLOW/VERIFY/BLOCK), reason, timestamp | Every risk evaluation is persisted permanently. Provides a complete audit trail of every access decision for incident response. |
| `trusted_device.py` | `trusted_devices` | id, user_id, device_fingerprint, device_label, first_seen_at, last_seen_at, is_active | Known device fingerprints per user. If a new fingerprint appears (not in this table), the "new_device_detected" signal fires. |
| `revoked_token.py` | `revoked_tokens` | jti (JWT ID), user_id, expires_at, revoked_at, reason (LOGOUT/ROTATED) | Blacklist of revoked JWTs. When a user logs out, their access token's JTI is added here. When a refresh token is rotated, the old one is added. Any token in this table is rejected on subsequent use. |

---

## 7. Service Layer: `app/services/` — Business Logic

### `auth_service.py` — User Management & Authentication

**`create_user()`**:
1. Checks if username already exists → raises `DuplicateUsernameError` (HTTP 409)
2. Validates password policy (uppercase, digit, special char, min 8 chars) → raises `PasswordPolicyError` (HTTP 422)
3. Hashes password with bcrypt
4. Inserts into `users` table

**`authenticate_user()`**:
1. Looks up user by username
2. Checks if account is locked (`locked_until > now`)
3. Verifies bcrypt hash
4. On failure: increments `failed_login_attempts`, locks account after 5 failures
5. On success: resets `failed_login_attempts` to 0, updates `last_login_at` and `last_login_ip`

**`revoke_token()` / `is_token_revoked()`**:
- Adds a token's JTI to the `revoked_tokens` table
- Used by logout (reason="LOGOUT") and refresh rotation (reason="ROTATED")

### `mfa_service.py` — MFA Challenge Management

**`create_challenge()`**:
1. Checks that the user has fewer than `MFA_MAX_ACTIVE_CHALLENGES` (3) pending challenges
2. Creates a new UUID challenge with 5-minute TTL
3. Returns the challenge_id for the client to echo back

**`validate_and_consume()`**:
1. Looks up the challenge by UUID
2. Verifies it belongs to the requesting user (prevents **cross-user attacks**)
3. Checks it hasn't expired
4. Checks it hasn't already been used (prevents **replay attacks**)
5. Marks it as `used=True`

### `behaviour_monitor.py` — The Core Detection Engine

This is the heart of the project. It runs **7 behavioural signal checks**:

**Signals 1-3 (Counter-based, Redis-backed)**:
- Uses Redis `INCR` + `EXPIRE` for fast counting in time windows
- Falls back to MySQL `COUNT()` query if Redis is unavailable

**Signals 4-7 (Context-based, DB reads)**:
- Query the database for device fingerprints, IP history, login timestamps

See [Section 9](#9-the-7-signal-risk-engine--how-detection-works) for full details.

### `risk_engine.py` — Weighted Scoring

**`calculate_risk_score()`**: Sums the weight of each triggered signal.

**`determine_decision()`**: Maps the score to ALLOW/VERIFY/BLOCK using configurable thresholds.

**`evaluate_and_store()`**: Computes the score, persists the decision to `risk_decisions` table, returns the result.

### `decision_controller.py` — Orchestrator

Combines the monitor and engine into a single call:
```
analyse_behaviour() → list of triggered signals
     ↓
evaluate_and_store() → RiskDecision record
     ↓
return { risk_score, decision, triggered_signals }
```

### `audit_logger.py` — Tamper-Evident Hash Chain

See [Section 10](#10-the-tamper-evident-audit-chain) for full details.

Key design decisions:
- `prev_hash` is fetched BEFORE the new row is flushed (otherwise the NULL chain_hash of the flushed row would be picked up)
- Timestamp is truncated to whole seconds (MySQL DATETIME doesn't store microseconds, so the isoformat() string must match at write and verify time)

### `session_service.py` — Login Session Management

- `create_session()`: Creates a new session record with IP, timestamps, expiry
- `is_session_active()`: Checks if session exists and hasn't expired
- `touch_session()`: Updates `last_active_at` on each request
- `terminate_session()`: Sets `is_active=False` with a reason (LOGOUT, EXPIRED, etc.)

### `device_service.py` — Trusted Device Registry

- `register_device()`: Adds a new device fingerprint or updates `last_seen_at` for known devices
- Used by the `new_device_detected` signal check — if the fingerprint isn't in `trusted_devices`, the signal fires

---

## 8. API Layer: `app/api/` — Endpoints

### `schemas.py` — Pydantic Request/Response Models

**Why separate from ORM models?** To prevent accidentally exposing internal fields like `password_hash` or `chain_hash` in API responses. Pydantic schemas define exactly what goes in and out.

Key schemas:
- `RegisterRequest`: username (3-64 chars, alphanumeric pattern), password (8-128 chars)
- `LoginResponse`: access_token, refresh_token, token_type, user_id, username, session_id
- `MFARespondRequest`: user_id, challenge_id, approved (boolean)
- `RiskEvaluationResponse`: user_id, triggered_signals, risk_score, decision, reason
- `ChainVerifyResponse`: user_id, valid (boolean), events_checked, broken_at_event_id

### `auth.py` — Authentication Routes

| Route | What It Does |
|-------|--------------|
| `POST /api/register` | Validates password policy, hashes with bcrypt, creates user. Returns 201 on success, 409 for duplicate username, 422 for policy violations. Rate-limited to 5/min. |
| `POST /api/login` | Verifies credentials, checks lockout, issues JWT access + refresh token pair, creates a session, registers the device. Rate-limited to 10/min. |
| `POST /api/logout` | Revokes the access token (adds JTI to blacklist), terminates the session. Idempotent — second logout with same token doesn't crash. |
| `POST /api/refresh` | Accepts a refresh token, validates it, revokes the old one (rotation), issues a new pair. Rejects access tokens (wrong type claim), garbage tokens, and already-revoked tokens. |

### `mfa.py` — MFA Routes

| Route | What It Does |
|-------|--------------|
| `POST /api/mfa/request?user_id=N&session_id=S` | Issues a new MFA challenge (UUID). Enforces max 3 active challenges per user. Returns 404 for unknown users. Rate-limited to 20/min. |
| `POST /api/mfa/respond` | Approves or denies a challenge. Runs the full behaviour analysis + risk evaluation pipeline. Returns the risk decision. Blocks replay attacks, cross-user attacks, and expired challenges. |

### `risk.py` — Risk Evaluation Routes

| Route | What It Does |
|-------|--------------|
| `GET /api/risk/evaluate?user_id=N` | Runs all 7 behavioural checks on-demand and returns the risk score, decision, and triggered signals. |
| `GET /api/risk/audit?user_id=N` | Verifies the tamper-evident hash chain for a user. Returns `valid: true/false` and `broken_at_event_id` if tampering is detected. |

### `logs.py` — Read-Only Log Endpoints

| Route | What It Returns |
|-------|-----------------|
| `GET /api/logs/events?user_id=N` | Authentication event history (login, MFA, logout events) |
| `GET /api/logs/decisions?user_id=N` | Risk decision history (scores, decisions, reasons) |
| `GET /api/logs/devices?user_id=N` | Trusted device list for a user |
| `GET /api/logs/sessions?user_id=N` | Login session history (active and terminated) |

### `pages.py` — HTML Page Routes

| Route | Template | What It Shows |
|-------|----------|---------------|
| `GET /` | `login.html` | Login form |
| `GET /register` | `register.html` | Registration form with password policy hints |
| `GET /mfa` | `mfa.html` | MFA challenge screen with Approve/Deny buttons |
| `GET /dashboard` | `dashboard.html` | Security monitoring dashboard with event logs, risk scores, sessions |

---

## 9. The 7-Signal Risk Engine — How Detection Works

When a user performs an action (login, MFA approve), the system runs all 7 behavioural checks:

```
Signal                      Trigger Condition                            Weight
---------------------------------------------------------------------------
1. excess_mfa_requests      >= 3 MFA requests within 2 minutes            +30
2. rapid_login_attempts     >= 5 login attempts within 5 minutes           +20
3. repeated_approvals       >= 3 MFA approvals within 2 minutes            +25
4. new_device_detected      Device fingerprint not in trusted_devices      +20
5. ip_change_detected       Different /24 subnet than previous login       +15
6. impossible_travel        2+ IPs sharing < 2 octets within 1 hour        +40
7. off_hours_access         Login between 10 PM and 6 AM (UTC)             +10
```

### How the Score Maps to a Decision

```
Score = sum of all triggered signal weights

  0 - 39   -->  ALLOW   (normal access)
  40 - 69  -->  VERIFY  (step-up authentication required)
  70+      -->  BLOCK   (access denied)

Maximum possible score: 30+20+25+20+15+40+10 = 160 --> always BLOCK if all fire
```

### Examples

| Scenario | Signals Triggered | Score | Decision |
|----------|-------------------|-------|----------|
| Normal login from known device | None | 0 | ALLOW |
| Login from a new laptop | new_device_detected | 20 | ALLOW |
| Attacker spams 5 MFA pushes | excess_mfa_requests | 30 | ALLOW |
| MFA fatigue attack (spam + approvals) | excess_mfa_requests + repeated_approvals | 55 | VERIFY |
| Full attack from unknown device | excess_mfa + repeated + new_device | 75 | BLOCK |
| Impossible travel + off hours | impossible_travel + off_hours_access | 50 | VERIFY |

### Redis vs MySQL for Signal Counting

- **Signals 1-3** use Redis `INCR` with `EXPIRE` for sub-millisecond counting
- If Redis is down, these fall back to MySQL `COUNT()` with time window filters
- **Signals 4-7** always use MySQL (lower frequency, need full DB context)

---

## 10. The Tamper-Evident Audit Chain

Every event in `auth_events` has a `chain_hash` field that links it to the previous event:

```
Event 1: chain_hash = SHA-256("000...000" | event_id | user_id | type | timestamp)
                        ^-- GENESIS_HASH (64 zeros, the seed)

Event 2: chain_hash = SHA-256(Event1.hash | event_id | user_id | type | timestamp)

Event 3: chain_hash = SHA-256(Event2.hash | event_id | user_id | type | timestamp)
```

### Why This Exists

If an attacker or rogue admin modifies any row in the database (changes an IP address, deletes an event, alters a timestamp), the chain breaks from that point forward. The `/api/risk/audit?user_id=X` endpoint recomputes every link and reports exactly where the chain breaks.

### How Verification Works

```python
# Pseudocode for verify_chain():
prev_hash = "000...000"  # GENESIS_HASH
for event in user_events_ordered_by_id:
    expected = SHA256(prev_hash | event.id | event.user_id | event.type | event.timestamp)
    if event.chain_hash != expected:
        return {"valid": False, "broken_at_event_id": event.id}
    prev_hash = event.chain_hash
return {"valid": True, "events_checked": count}
```

### Key Implementation Details

- `prev_hash` is fetched **before** `db.flush()` — otherwise the newly-flushed row (with chain_hash=NULL) would be the "most recent" and incorrectly return GENESIS_HASH
- Timestamp is truncated to whole seconds with `.replace(microsecond=0)` — MySQL `DATETIME` doesn't store microseconds, so the `isoformat()` string must match at write time and verify time

---

## 11. JWT Authentication & Token Lifecycle

### Token Types

| Token | Lifetime | Purpose | Stored In |
|-------|----------|---------|-----------|
| Access Token | 30 minutes | Authorizes API requests. Carried in `Authorization: Bearer <token>` header. | Client-side (JavaScript memory) |
| Refresh Token | 7 days | Obtains a new access token without re-entering credentials. | Client-side (httpOnly cookie or localStorage) |

### Token Claims (Payload)

```json
{
  "sub": "5",              // user_id as string
  "username": "alice",
  "jti": "uuid-v4",        // unique token ID (for revocation tracking)
  "type": "access",        // or "refresh"
  "exp": 1710000000,       // expiration timestamp
  "iat": 1709998200        // issued-at timestamp
}
```

### Refresh Token Rotation

When the client calls `POST /api/refresh`:
1. Old refresh token is validated (signature, expiry, type="refresh")
2. Old refresh token's JTI is added to `revoked_tokens` (reason="ROTATED")
3. New access + refresh token pair is issued
4. If someone tries to use the old refresh token again → 401 Unauthorized

This prevents **token theft**: if an attacker steals a refresh token, the legitimate user's next refresh will invalidate the stolen one.

### Revocation Flow

```
Logout:
  1. Access token JTI added to revoked_tokens (reason="LOGOUT")
  2. Session terminated in login_sessions
  3. Any subsequent use of that access token is rejected

Refresh:
  1. Old refresh token JTI added to revoked_tokens (reason="ROTATED")
  2. New token pair issued
  3. Old refresh token can never be used again
```

---

## 12. All UIs — Swagger, ReDoc, Browser Pages

### 1. Swagger UI — `http://localhost:8001/docs`

FastAPI **auto-generates** this from route function signatures and Pydantic schemas. You do NOT write any code for this — it comes free with FastAPI.

Features:
- Lists every API endpoint grouped by tag
- Shows request parameters, body schema, and response schema
- **Interactive "Try it out" button** — fill in parameters, click Execute, see the live response
- Shows curl commands for each request

Enabled by: `docs_url="/docs"` in `main.py`

### 2. ReDoc — `http://localhost:8001/redoc`

Alternative API documentation viewer, also auto-generated by FastAPI. Provides:
- Cleaner, more readable documentation layout
- Better for sharing with team members who need to understand the API
- Less interactive than Swagger (no "Try it out" button)

Enabled by: `redoc_url="/redoc"` in `main.py`

### 3. Browser UI — `http://localhost:8001/`

Four HTML pages served by `pages.py` using Jinja2 templates:

| Page | URL | Purpose |
|------|-----|---------|
| Login | `/` | Username/password form. Calls `POST /api/login`, stores JWT in localStorage, redirects to `/mfa` |
| Register | `/register` | Registration form. Shows real-time password policy hints. Calls `POST /api/register` |
| MFA | `/mfa` | Shows the MFA challenge. Approve/Deny buttons call `POST /api/mfa/respond`. Displays risk decision result |
| Dashboard | `/dashboard` | Security monitoring panel. Shows recent auth events, risk decisions, active sessions, triggered signals. Auto-refreshes |

All templates use **Tailwind CSS** via CDN for styling — no npm or build step.

### 4. Health Endpoint — `http://localhost:8001/health`

```json
{"status": "ok", "version": "2.0.0", "service": "Adaptive Auth System"}
```

Used by load balancers, container orchestrators (Kubernetes), and monitoring tools to check if the server is alive.

---

## 13. Database Schema (v2)

### `users`
| Column | Type | Notes |
|--------|------|-------|
| id | INT AUTO_INCREMENT PK | |
| username | VARCHAR(64) UNIQUE | Alphanumeric + underscore + hyphen only |
| password_hash | VARCHAR(128) | bcrypt hash, never plain text |
| failed_login_attempts | INT DEFAULT 0 | Counter for lockout logic |
| locked_until | DATETIME NULL | When the lockout expires |
| last_login_at | DATETIME NULL | Used by IP change detection |
| last_login_ip | VARCHAR(45) NULL | Used by IP change detection |
| created_at | DATETIME | |

### `auth_events`
| Column | Type | Notes |
|--------|------|-------|
| event_id | INT AUTO_INCREMENT PK | |
| user_id | INT FK -> users.id | ON DELETE CASCADE |
| event_type | ENUM(LOGIN, MFA_REQUEST, APPROVE, DENY, LOGOUT, TOKEN_REVOKE, LOCKOUT) | |
| ip_address | VARCHAR(45) | Supports IPv6 |
| device_info | VARCHAR(256) | User-Agent string |
| device_fingerprint | VARCHAR(64) | SHA-256 of IP+UA+Lang |
| session_id | VARCHAR(64) | FK to login_sessions |
| success | BOOLEAN DEFAULT TRUE | FALSE for failed logins |
| chain_hash | VARCHAR(64) | Tamper-evident linked hash |
| timestamp | DATETIME | |

### `mfa_challenges`
| Column | Type | Notes |
|--------|------|-------|
| id | INT AUTO_INCREMENT PK | |
| challenge_id | VARCHAR(36) UNIQUE | UUID v4 |
| user_id | INT FK -> users.id | |
| expires_at | DATETIME | TTL = 5 minutes |
| used | BOOLEAN DEFAULT FALSE | Prevents replay |

### `login_sessions`
| Column | Type | Notes |
|--------|------|-------|
| session_id | VARCHAR(36) PK | UUID v4 |
| user_id | INT FK -> users.id | |
| ip_address | VARCHAR(45) | |
| created_at | DATETIME | |
| last_active_at | DATETIME | Updated on each request |
| expires_at | DATETIME | |
| is_active | BOOLEAN | |
| terminated_reason | VARCHAR(64) NULL | LOGOUT, EXPIRED, etc. |

### `risk_decisions`
| Column | Type | Notes |
|--------|------|-------|
| decision_id | INT AUTO_INCREMENT PK | |
| user_id | INT FK -> users.id | |
| risk_score | INT | 0-160 |
| decision | ENUM(ALLOW, VERIFY, BLOCK) | |
| reason | VARCHAR(512) | Human-readable explanation |
| timestamp | DATETIME | |

### `trusted_devices`
| Column | Type | Notes |
|--------|------|-------|
| id | INT AUTO_INCREMENT PK | |
| user_id | INT FK -> users.id | |
| device_fingerprint | VARCHAR(64) | SHA-256 hash |
| device_label | VARCHAR(128) NULL | Optional user-facing name |
| first_seen_at | DATETIME | |
| last_seen_at | DATETIME | Updated on each use |
| is_active | BOOLEAN | Can be deactivated |

### `revoked_tokens`
| Column | Type | Notes |
|--------|------|-------|
| id | INT AUTO_INCREMENT PK | |
| jti | VARCHAR(36) UNIQUE INDEX | JWT ID being revoked |
| user_id | INT | |
| expires_at | DATETIME | Original token expiry (for cleanup) |
| revoked_at | DATETIME | When revocation happened |
| reason | VARCHAR(32) | LOGOUT or ROTATED |

---

## 14. API Endpoints — Complete Reference

| Method | Endpoint | Rate Limit | Auth | Request Body | Success | Error Codes |
|--------|----------|------------|------|--------------|---------|-------------|
| POST | `/api/register` | 5/min | None | `{username, password}` | 201 + user object | 409 (duplicate), 422 (policy/validation) |
| POST | `/api/login` | 10/min | None | `{username, password}` | 200 + JWT pair + session_id | 401 (wrong creds or locked) |
| POST | `/api/logout` | — | Bearer token | `{session_id}` | 200 | — |
| POST | `/api/refresh` | — | None | `{refresh_token}` | 200 + new JWT pair | 401 (invalid/revoked/wrong type) |
| POST | `/api/mfa/request` | 20/min | Query params | `?user_id=N&session_id=S` | 200 + challenge_id | 404 (user not found), 429 |
| POST | `/api/mfa/respond` | 20/min | None | `{user_id, challenge_id, approved}` | 200 + risk decision | 400 (replay/expired/cross-user), 404 |
| GET | `/api/risk/evaluate` | — | Query param | `?user_id=N` | 200 + score + decision | 404 |
| GET | `/api/risk/audit` | — | Query param | `?user_id=N` | 200 + valid/broken chain | 404 |
| GET | `/api/logs/events` | — | Query param | `?user_id=N&limit=50` | 200 + event list | — |
| GET | `/api/logs/decisions` | — | Query param | `?user_id=N&limit=50` | 200 + decision list | — |
| GET | `/api/logs/devices` | — | Query param | `?user_id=N` | 200 + device list | — |
| GET | `/api/logs/sessions` | — | Query param | `?user_id=N` | 200 + session list | — |
| GET | `/health` | — | None | — | 200 + status/version | — |

---

## 15. Security Features Summary

| Feature | Implementation | OWASP Category |
|---------|----------------|----------------|
| Password hashing | bcrypt with random salt per user | Credential Storage |
| Password policy | Min 8 chars, uppercase, digit, special char enforced at registration | Authentication |
| Account lockout | Lock after 5 failed logins, auto-unlock after 15 min | Brute Force Protection |
| User enumeration prevention | 401 for both wrong password AND non-existent user (same error message) | Information Disclosure |
| JWT with revocation | Access + refresh tokens; blacklist stored in `revoked_tokens` table | Session Management |
| Refresh token rotation | Old refresh token invalidated after each use | Token Theft Protection |
| MFA replay prevention | Challenge marked `used=True` after first response | Replay Attack |
| MFA cross-user prevention | Challenge's `user_id` must match the responding user | Authorization |
| Rate limiting | 10 login/min, 5 register/min, 20 MFA/min per IP | Brute Force / DoS |
| Security headers | X-Frame-Options: DENY, CSP, nosniff, referrer-policy, permissions-policy, X-XSS-Protection | HTTP Security |
| CORS policy | Restricted to configured origins only | Cross-Origin |
| Tamper-evident audit chain | SHA-256 linked hash chain on all auth events | Audit / Integrity |
| Structured JSON logging | Machine-parseable logs for all auth events and decisions | Monitoring |
| Graceful Redis fallback | App works without Redis, falls back to MySQL queries | Availability |

---

## 16. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `Adaptive Auth System` | Application display name |
| `ENVIRONMENT` | `development` | `development` or `production` (enables HSTS in production) |
| `DEBUG` | `False` | Enable debug logging |
| `ALLOWED_ORIGINS` | `http://localhost:8000` | Comma-separated CORS origins |
| `DB_HOST` | `localhost` | MySQL host |
| `DB_PORT` | `3306` | MySQL port |
| `DB_NAME` | `adaptive_auth` | Database name |
| `DB_USER` | `root` | MySQL username |
| `DB_PASSWORD` | `password` | MySQL password **(change in production)** |
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database number |
| `REDIS_PASSWORD` | (empty) | Redis auth password |
| `SECRET_KEY` | (default) | JWT signing key **(change in production — use `secrets.token_hex(32)`)** |
| `ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `MAX_FAILED_LOGINS` | `5` | Lock account after this many failures |
| `LOCKOUT_DURATION_MINUTES` | `15` | How long the lockout lasts |
| `PASSWORD_MIN_LENGTH` | `8` | Minimum password length |
| `PASSWORD_REQUIRE_UPPER` | `True` | Require uppercase letter |
| `PASSWORD_REQUIRE_DIGIT` | `True` | Require digit |
| `PASSWORD_REQUIRE_SPECIAL` | `True` | Require special character |
| `MFA_CHALLENGE_TTL_SECONDS` | `300` | Challenge expires after 5 min |
| `MFA_MAX_ACTIVE_CHALLENGES` | `3` | Max pending challenges per user |
| `MFA_WINDOW_SECONDS` | `120` | Lookback for MFA signal (2 min) |
| `LOGIN_WINDOW_SECONDS` | `300` | Lookback for login signal (5 min) |
| `APPROVAL_WINDOW_SECONDS` | `120` | Lookback for approval signal (2 min) |
| `MFA_REQUEST_LIMIT` | `3` | MFA requests before signal fires |
| `LOGIN_ATTEMPT_LIMIT` | `5` | Login attempts before signal fires |
| `APPROVAL_LIMIT` | `3` | Approvals before signal fires |
| `WEIGHT_EXCESS_MFA` | `30` | Risk points for excess MFA |
| `WEIGHT_RAPID_LOGIN` | `20` | Risk points for rapid logins |
| `WEIGHT_REPEATED_APPROVALS` | `25` | Risk points for repeated approvals |
| `WEIGHT_NEW_DEVICE` | `20` | Risk points for new device |
| `WEIGHT_IP_CHANGE` | `15` | Risk points for IP change |
| `WEIGHT_IMPOSSIBLE_TRAVEL` | `40` | Risk points for impossible travel |
| `WEIGHT_OFF_HOURS` | `10` | Risk points for off-hours access |
| `THRESHOLD_ALLOW` | `39` | Scores <= this = ALLOW |
| `THRESHOLD_VERIFY` | `69` | Scores <= this = VERIFY, above = BLOCK |
| `RATE_LIMIT_LOGIN` | `10/minute` | Login endpoint rate limit |
| `RATE_LIMIT_REGISTER` | `5/minute` | Register endpoint rate limit |
| `RATE_LIMIT_MFA` | `20/minute` | MFA endpoint rate limit |
| `OFF_HOURS_START` | `22` | 10 PM (start of off-hours) |
| `OFF_HOURS_END` | `6` | 6 AM (end of off-hours) |

---

## 17. Installation & Setup

### Prerequisites

| Tool | Minimum Version |
|------|----------------|
| Python | 3.11+ |
| MySQL Server | 8.0+ |
| pip | latest |
| Redis (optional) | 5.0+ |

### Step 1 — Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Create MySQL database

```sql
CREATE DATABASE adaptive_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Step 4 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set:
```
DB_PASSWORD=your_mysql_password
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
```

### Step 5 — Start the server

```bash
py -m uvicorn app.main:app --host 0.0.0.0 --port 8001
```

Database tables are created automatically on first start.

---

## 18. Running the Application

### URLs

| URL | What |
|-----|------|
| `http://localhost:8001/` | Login page (browser UI) |
| `http://localhost:8001/register` | Registration page |
| `http://localhost:8001/mfa` | MFA approve/deny page |
| `http://localhost:8001/dashboard` | Security dashboard |
| `http://localhost:8001/docs` | Swagger UI (interactive API testing) |
| `http://localhost:8001/redoc` | ReDoc API documentation |
| `http://localhost:8001/health` | Health check endpoint |

### Normal Login Flow

1. Go to `/register` and create an account
2. Go to `/` and log in
3. System issues an MFA challenge, redirects to `/mfa`
4. Click **Approve** — risk score = 0, decision = ALLOW
5. Redirected to `/dashboard`

---

## 19. Test Scripts — What They Cover

### `tests/simulate_attacks.py` — 3 Attack Scenarios

Run with: `py tests/simulate_attacks.py --base-url http://localhost:8001`

| Scenario | What Happens | Expected Result |
|----------|-------------|-----------------|
| 1. Legitimate Login | Register, login, MFA approve (once) | Score = 0, Decision = ALLOW |
| 2. MFA Fatigue Attack | 5 rapid MFA pushes + 4 approvals | Score >= 40, Decision = VERIFY or BLOCK |
| 3. Brute-Force Login | 6 wrong passwords | Account locked after 5 failures, correct password also rejected |

### `tests/test_edge_cases.py` — 37 Security Edge-Case Tests

Run with: `py tests/test_edge_cases.py --base-url http://localhost:8001`

| Module | Test IDs | Tests |
|--------|----------|-------|
| 1 — Password Policy | TEST-PW-01 to 07 | Valid password accepted, duplicate username (409), no uppercase (422), too short (422), no special char (422), no digit (422), invalid username format (422) |
| 2 — Auth & Lockout | TEST-AUTH-01 to 05 | Wrong password (401), non-existent user returns 401 (not 404), account locked after 5 failures, correct password rejected while locked, clean login succeeds |
| 3 — MFA Security | TEST-MFA-01 to 07b | Issue challenge, approve once, replay blocked, fake UUID rejected, cross-user claim blocked, unknown user (404), denial consumed + replay blocked |
| 7 — Audit Chain | TEST-AUDIT-01/02 | Chain intact for fresh user, unknown user returns 404 |
| 8 — JWT Security | TEST-JWT-01 to 07 | Logout, idempotent second logout, refresh rotation, old refresh rejected, new refresh valid, access token on /refresh rejected, garbage token rejected |
| 9 — Security Headers | 6 tests | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, Content-Security-Policy |
| 10 — Rate Limiting | TEST-RATE-01/02 | Login rate limit (429 at request #11), register rate limit (429 at request #6) |

Each test module uses a unique `X-Forwarded-For` IP address so rate-limit buckets don't interfere with each other.

---

## 20. Data Flow: Login to Risk Decision

```
1. POST /api/register
   --> password policy check (uppercase, digit, special, length)
   --> bcrypt hash the password
   --> INSERT INTO users

2. POST /api/login
   --> look up user by username
   --> check locked_until (is account locked?)
   --> verify bcrypt hash
   --> on failure: increment failed_login_attempts
   --> on success: reset counter, issue JWT pair, create session, register device
   --> log_event(LOGIN) with chain_hash

3. POST /api/mfa/request?user_id=5&session_id=abc
   --> check user exists
   --> check < 3 active challenges
   --> create challenge (UUID, 5-min TTL)
   --> log_event(MFA_REQUEST)

4. POST /api/mfa/respond {user_id: 5, challenge_id: "uuid", approved: true}
   --> validate_and_consume challenge:
       - exists? belongs to this user? not expired? not already used?
   --> mark challenge as used=True (prevents replay)
   --> log_event(APPROVE)
   --> analyse_behaviour():
       Signal 1: COUNT MFA_REQUEST events in last 2 min (Redis or MySQL)
       Signal 2: COUNT LOGIN events in last 5 min
       Signal 3: COUNT APPROVE events in last 2 min
       Signal 4: device_fingerprint in trusted_devices?
       Signal 5: IP changed from last login?
       Signal 6: distant IP within 1 hour?
       Signal 7: current hour between 10PM-6AM?
   --> calculate_risk_score(triggered_signals):
       score = sum of weights
   --> determine_decision(score):
       0-39 = ALLOW, 40-69 = VERIFY, 70+ = BLOCK
   --> INSERT INTO risk_decisions
   --> return {risk_score: 55, decision: "VERIFY", triggered_signals: [...]}
```

---

## 21. Bugs Found and Fixed During Testing

These bugs were discovered by running `test_edge_cases.py` against the live server:

### Bug 1: Password Policy Returned Wrong HTTP Status

**Symptom**: Password policy violations returned `409 Conflict` instead of `422 Unprocessable Entity`.

**Root Cause**: `create_user()` raised `ValueError` for both duplicate usernames AND policy violations. The handler caught all `ValueError` and returned 409.

**Fix**: Created two exception subclasses - `DuplicateUsernameError` (→ 409) and `PasswordPolicyError` (→ 422).

### Bug 2: Rate-Limit Buckets Shared Across Test Modules

**Symptom**: Module 2 (lockout) tests hit 429 before accumulating 5 failures because Module 1 tests had already consumed part of the 10/minute login budget.

**Root Cause**: All tests came from `127.0.0.1`, sharing one rate-limit bucket.

**Fix**: Updated `limiter.py` to read `X-Forwarded-For` header. Each test module sends a unique fake IP (10.0.1.1 for passwords, 10.0.2.1 for auth, etc.).

### Bug 3: Double Logout Caused 500 Internal Server Error

**Symptom**: Calling `POST /api/logout` twice with the same access token crashed with `IntegrityError`.

**Root Cause**: `revoke_token()` did an unconditional INSERT. The second call tried to insert a duplicate JTI (unique constraint violation).

**Fix**: Added `is_token_revoked()` check before calling `revoke_token()` in the logout handler. Second logout is now idempotent.

### Bug 4: Audit Chain Always Broken After First Event

**Symptom**: `GET /api/risk/audit` reported chain broken at the second event for every user.

**Root Cause (part A)**: `_get_last_chain_hash()` was called AFTER `db.flush()`. The flushed row (chain_hash=NULL) was the most recent, so `prev_hash` resolved to `GENESIS_HASH` for every event.

**Root Cause (part B)**: Timestamp at write time was `datetime.now(timezone.utc)` with microseconds (`2026-03-08T08:54:44.678901+00:00`). MySQL `DATETIME` truncates microseconds, so at verification time the timestamp was `2026-03-08T08:54:44` — different isoformat string → different SHA-256 hash.

**Fix**: (A) Moved `_get_last_chain_hash()` call to before `db.flush()`. (B) Changed to `datetime.utcnow().replace(microsecond=0)` so write-time and read-time timestamps produce identical isoformat strings.

---

## Quick Reference Card

```
Start server:    py -m uvicorn app.main:app --host 0.0.0.0 --port 8001
Run attacks:     py tests/simulate_attacks.py --base-url http://localhost:8001
Run edge tests:  py tests/test_edge_cases.py --base-url http://localhost:8001
Swagger UI:      http://localhost:8001/docs
Dashboard:       http://localhost:8001/dashboard
Health check:    curl http://localhost:8001/health
```
