# Adaptive Auth System v2 — Complete Testing Guide

> **Audience:** QA engineers, security auditors, academic evaluators
> **System:** Behaviour-Based Adaptive Authentication with MFA Fatigue Detection
> **Version:** 2.0.0 (production-grade)

---

## Table of Contents

1. [Test Environment Setup](#1-test-environment-setup)
2. [System Health Verification](#2-system-health-verification)
3. [Module 1 — User Registration & Password Policy](#3-module-1--user-registration--password-policy)
4. [Module 2 — Authentication & Account Lockout](#4-module-2--authentication--account-lockout)
5. [Module 3 — MFA Challenge Lifecycle](#5-module-3--mfa-challenge-lifecycle)
6. [Module 4 — Risk Engine & Behaviour Signals](#6-module-4--risk-engine--behaviour-signals)
7. [Module 5 — MFA Fatigue Attack Detection](#7-module-5--mfa-fatigue-attack-detection)
8. [Module 6 — Brute-Force Attack Detection](#8-module-6--brute-force-attack-detection)
9. [Module 7 — Tamper-Evident Audit Chain](#9-module-7--tamper-evident-audit-chain)
10. [Module 8 — JWT Security & Token Revocation](#10-module-8--jwt-security--token-revocation)
11. [Module 9 — Security Headers](#11-module-9--security-headers)
12. [Module 10 — Rate Limiting](#12-module-10--rate-limiting)
13. [Automated Attack Simulation](#13-automated-attack-simulation)
14. [Dashboard Visual Testing](#14-dashboard-visual-testing)
15. [Database Verification (SQL)](#15-database-verification-sql)
16. [Risk Score Reference Table](#16-risk-score-reference-table)
17. [Complete API Reference Card](#17-complete-api-reference-card)

---

## 1. Test Environment Setup

### Prerequisites

| Component | Requirement | Verify with |
|-----------|-------------|-------------|
| Python    | 3.10 – 3.14 | `python --version` |
| MySQL     | 8.0+        | `mysql --version` |
| Redis     | 6.0+ (optional) | `redis-cli ping` |
| httpx     | installed   | `pip show httpx` |

### Start the Server

```bash
# 1. Copy environment file
cp .env.example .env

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start MySQL and create database
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS adaptive_auth;"

# 4. (Optional) Start Redis
redis-server

# 5. Start the application
py -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Expected startup output:
```
INFO:     DB tables synchronised
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Test Tools

All tests below use `curl`. Install alternatives if preferred:
- **Postman** — import the API reference at the end of this guide
- **HTTPie** — `pip install httpie`
- **Swagger UI** — open `http://localhost:8000/docs` and use "Try it out"

---

## 2. System Health Verification

### TEST-001 — Server Liveness

**Purpose:** Confirm the API is running and returning version info.

```bash
curl -s http://localhost:8000/health | python -m json.tool
```

**Expected Response (HTTP 200):**
```json
{
  "status": "ok",
  "version": "2.0.0",
  "service": "Adaptive Auth System"
}
```

**Pass Criteria:** `status` is `"ok"`, `version` is `"2.0.0"`.

---

### TEST-002 — OpenAPI Documentation

**Purpose:** Confirm interactive docs are accessible.

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/docs
```

**Expected:** `200`

Open in browser: `http://localhost:8000/docs`
You should see the Swagger UI with all 14 endpoints listed.

---

## 3. Module 1 — User Registration & Password Policy

### TEST-003 — Successful Registration

```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "Secure@Pass1"}' \
  | python -m json.tool
```

**Expected Response (HTTP 201):**
```json
{
  "user_id": 1,
  "username": "alice",
  "message": "User registered successfully"
}
```

---

### TEST-004 — Duplicate Username Rejection

```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "Secure@Pass1"}' \
  | python -m json.tool
```

**Expected Response (HTTP 409):**
```json
{
  "detail": "Username already registered"
}
```

---

### TEST-005 — Weak Password: No Uppercase

```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "weakpass1!"}' \
  | python -m json.tool
```

**Expected Response (HTTP 422):**
```json
{
  "detail": "Password must contain at least one uppercase letter"
}
```

---

### TEST-006 — Weak Password: Too Short

```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "carol", "password": "Ab1!"}' \
  | python -m json.tool
```

**Expected Response (HTTP 422):**
```json
{
  "detail": "Password must be at least 8 characters long"
}
```

---

### TEST-007 — Weak Password: Missing Special Character

```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "dave", "password": "SecurePass1"}' \
  | python -m json.tool
```

**Expected Response (HTTP 422):**
```json
{
  "detail": "Password must contain at least one special character"
}
```

**Password Policy Summary:**

| Rule | Setting | Value |
|------|---------|-------|
| Min length | `PASSWORD_MIN_LENGTH` | 8 |
| Uppercase required | `PASSWORD_REQUIRE_UPPER` | True |
| Digit required | `PASSWORD_REQUIRE_DIGIT` | True |
| Special char required | `PASSWORD_REQUIRE_SPECIAL` | True |

---

## 4. Module 2 — Authentication & Account Lockout

### TEST-008 — Successful Login

First register a fresh test user:
```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "Test@Pass99"}' \
  | python -m json.tool
```

Then log in:
```bash
curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "Test@Pass99"}' \
  | python -m json.tool
```

**Expected Response (HTTP 200):**
```json
{
  "user_id": 2,
  "username": "testuser",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "session_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "token_type": "bearer"
}
```

Save these values for subsequent tests:
```bash
ACCESS_TOKEN="<access_token from response>"
USER_ID="<user_id from response>"
SESSION_ID="<session_id from response>"
```

---

### TEST-009 — Wrong Password Rejection

```bash
curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "WrongPass!"}' \
  | python -m json.tool
```

**Expected Response (HTTP 401):**
```json
{
  "detail": "Invalid credentials"
}
```

---

### TEST-010 — Account Lockout After 5 Failed Attempts

Run this 5 times in succession with a wrong password:

```bash
for i in 1 2 3 4 5; do
  echo "--- Attempt $i ---"
  curl -s -X POST http://localhost:8000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username": "testuser", "password": "WrongPass!"}' \
    | python -m json.tool
  sleep 0.5
done
```

**Expected Progression:**
- Attempts 1–4: `HTTP 401` — `"Invalid credentials"`
- Attempt 5: `HTTP 401` — `"Account locked due to too many failed attempts"`

---

### TEST-011 — Locked Account Rejects Valid Password

Immediately after lockout:
```bash
curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "Test@Pass99"}' \
  | python -m json.tool
```

**Expected Response (HTTP 401):**
```json
{
  "detail": "Account is temporarily locked. Try again later."
}
```

**Pass Criteria:** Even the correct password is rejected. Lockout duration is 15 minutes (`LOCKOUT_DURATION_MINUTES=15`).

**Verify in MySQL:**
```sql
SELECT username, failed_login_attempts, locked_until
FROM users WHERE username = 'testuser';
```

---

## 5. Module 3 — MFA Challenge Lifecycle

Register and login a fresh user for clean MFA tests:

```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "mfauser", "password": "Mfa@Test99"}' \
  | python -m json.tool

LOGIN=$(curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "mfauser", "password": "Mfa@Test99"}')

echo $LOGIN | python -m json.tool
```

Extract `user_id` and `session_id` from the response.

---

### TEST-012 — Issue MFA Challenge

```bash
curl -s -X POST \
  "http://localhost:8000/api/mfa/request?user_id=<MFA_USER_ID>&session_id=<MFA_SESSION>" \
  | python -m json.tool
```

**Expected Response (HTTP 200):**
```json
{
  "challenge_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "message": "MFA challenge issued",
  "expires_in_seconds": 300
}
```

Save: `CHALLENGE_ID="<challenge_id>"`

---

### TEST-013 — Approve MFA Challenge

```bash
curl -s -X POST http://localhost:8000/api/mfa/respond \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": <MFA_USER_ID>,
    "challenge_id": "<CHALLENGE_ID>",
    "approved": true
  }' | python -m json.tool
```

**Expected Response (HTTP 200):**
```json
{
  "status": "approved",
  "risk_decision": "ALLOW",
  "risk_score": 0,
  "triggered_signals": []
}
```

---

### TEST-014 — Deny MFA Challenge

Issue a new challenge, then deny it:

```bash
curl -s -X POST http://localhost:8000/api/mfa/respond \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": <MFA_USER_ID>,
    "challenge_id": "<NEW_CHALLENGE_ID>",
    "approved": false
  }' | python -m json.tool
```

**Expected Response (HTTP 200):**
```json
{
  "status": "denied",
  "risk_decision": "ALLOW",
  "risk_score": 0,
  "triggered_signals": []
}
```

---

### TEST-015 — Replay Attack Prevention

Try to use `CHALLENGE_ID` (already used in TEST-013) a second time:

```bash
curl -s -X POST http://localhost:8000/api/mfa/respond \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": <MFA_USER_ID>,
    "challenge_id": "<ALREADY_USED_CHALLENGE_ID>",
    "approved": true
  }' | python -m json.tool
```

**Expected Response (HTTP 400):**
```json
{
  "detail": "Challenge already used"
}
```

**Pass Criteria:** Challenge IDs are single-use. Replay attacks are blocked immediately.

---

### TEST-016 — Invalid Challenge ID

```bash
curl -s -X POST http://localhost:8000/api/mfa/respond \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": <MFA_USER_ID>,
    "challenge_id": "00000000-0000-0000-0000-000000000000",
    "approved": true
  }' | python -m json.tool
```

**Expected Response (HTTP 404):**
```json
{
  "detail": "Challenge not found"
}
```

---

## 6. Module 4 — Risk Engine & Behaviour Signals

### TEST-017 — Baseline Risk Evaluation (Clean User)

For a fresh user with no suspicious behaviour:

```bash
curl -s "http://localhost:8000/api/risk/evaluate?user_id=<MFA_USER_ID>" \
  | python -m json.tool
```

**Expected Response (HTTP 200):**
```json
{
  "user_id": 3,
  "risk_score": 0,
  "decision": "ALLOW",
  "triggered_signals": [],
  "reason": "Risk score within acceptable threshold"
}
```

---

### TEST-018 — Risk Score Arithmetic Verification

The 7 signals and their weights are:

| Signal | Weight | Trigger Condition |
|--------|--------|-------------------|
| `excess_mfa_requests` | +30 | >3 requests in 120s |
| `rapid_login_attempts` | +20 | >5 attempts in 300s |
| `repeated_approvals` | +25 | >3 approvals in 120s |
| `new_device_detected` | +20 | Device not in trusted list |
| `ip_change_detected` | +15 | IP differs from last login |
| `impossible_travel` | +40 | Multiple IPs in same session |
| `off_hours_access` | +10 | Access between 22:00–06:00 UTC |

Decision boundaries:
- Score 0–39 → **ALLOW**
- Score 40–69 → **VERIFY**
- Score 70+ → **BLOCK**

---

## 7. Module 5 — MFA Fatigue Attack Detection

### Setup: Create victim user

```bash
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "victim1", "password": "Victim@Pass1"}' \
  | python -m json.tool

VICTIM=$(curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "victim1", "password": "Victim@Pass1"}')

echo $VICTIM | python -m json.tool
# Save VICTIM_ID and VICTIM_SID from output
```

---

### TEST-019 — MFA Fatigue: Rapid Push Requests

Send 4 MFA requests rapidly (threshold: 3 requests/120s triggers the `excess_mfa_requests` signal):

```bash
for i in 1 2 3 4; do
  echo "--- MFA Request $i ---"
  curl -s -X POST \
    "http://localhost:8000/api/mfa/request?user_id=<VICTIM_ID>&session_id=<VICTIM_SID>" \
    | python -m json.tool
  sleep 0.2
done
```

**Expected:** All 4 return `challenge_id`. After the 3rd, `excess_mfa_requests` signal is armed.

---

### TEST-020 — MFA Fatigue: Repeated Approvals

Approve 4 challenges quickly (threshold: 3 approvals/120s triggers `repeated_approvals`):

```bash
# Issue 3 fresh challenges, collect IDs
C1=$(curl -s -X POST "http://localhost:8000/api/mfa/request?user_id=<VICTIM_ID>&session_id=<VICTIM_SID>" \
  | python -c "import sys,json; print(json.load(sys.stdin)['challenge_id'])")
C2=$(curl -s -X POST "http://localhost:8000/api/mfa/request?user_id=<VICTIM_ID>&session_id=<VICTIM_SID>" \
  | python -c "import sys,json; print(json.load(sys.stdin)['challenge_id'])")
C3=$(curl -s -X POST "http://localhost:8000/api/mfa/request?user_id=<VICTIM_ID>&session_id=<VICTIM_SID>" \
  | python -c "import sys,json; print(json.load(sys.stdin)['challenge_id'])")

# Approve all 3 rapidly
for CID in $C1 $C2 $C3; do
  curl -s -X POST http://localhost:8000/api/mfa/respond \
    -H "Content-Type: application/json" \
    -d "{\"user_id\": <VICTIM_ID>, \"challenge_id\": \"$CID\", \"approved\": true}" \
    | python -m json.tool
  sleep 0.1
done
```

**Expected — 3rd approval response:**
```json
{
  "risk_decision": "VERIFY",
  "triggered_signals": ["excess_mfa_requests", "repeated_approvals"]
}
```

---

### TEST-021 — Post-Attack Risk Evaluation

```bash
curl -s "http://localhost:8000/api/risk/evaluate?user_id=<VICTIM_ID>" \
  | python -m json.tool
```

**Expected:**
```json
{
  "risk_score": 55,
  "decision": "VERIFY",
  "triggered_signals": ["excess_mfa_requests", "repeated_approvals"]
}
```

Score breakdown: `excess_mfa(30) + repeated_approvals(25) = 55` → **VERIFY**

**Pass Criteria:** Decision is `VERIFY` or `BLOCK` — attack was detected.

---

## 8. Module 6 — Brute-Force Attack Detection

### TEST-022 — Brute-Force Login Simulation

```bash
# Register target
curl -s -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "brutetarget", "password": "Real@Pass99"}' \
  | python -m json.tool

# Send 6 wrong-password attempts
for i in 1 2 3 4 5 6; do
  echo "--- Attempt $i ---"
  curl -s -X POST http://localhost:8000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username": "brutetarget", "password": "WrongPass!"}' \
    | python -m json.tool
  sleep 0.2
done
```

**Expected Progression:**
- Attempts 1–4: `HTTP 401` — `"Invalid credentials"`
- Attempt 5: `HTTP 401` — `"Account locked due to too many failed attempts"`
- Attempt 6: `HTTP 401` — `"Account is temporarily locked. Try again later."`

---

### TEST-023 — Lockout Confirmed with Valid Credentials

```bash
curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "brutetarget", "password": "Real@Pass99"}' \
  | python -m json.tool
```

**Expected (HTTP 401):**
```json
{
  "detail": "Account is temporarily locked. Try again later."
}
```

**Pass Criteria:** Correct password rejected — lockout is enforced for all attempts.

---

## 9. Module 7 — Tamper-Evident Audit Chain

### TEST-024 — Audit Chain Integrity Verification

After any user has performed login and MFA actions:

```bash
curl -s "http://localhost:8000/api/risk/audit?user_id=<MFA_USER_ID>" \
  | python -m json.tool
```

**Expected Response (HTTP 200) — Chain intact:**
```json
{
  "valid": true,
  "events_checked": 7,
  "broken_at_event_id": null
}
```

**How the chain works:**
- Row 1: `chain_hash = SHA256("0"*64 | event_id | user_id | event_type | timestamp)`
- Row N: `chain_hash = SHA256(prev_row.chain_hash | event_id | user_id | event_type | timestamp)`
- Modifying any row invalidates all subsequent hashes.

---

### TEST-025 — Tamper Detection (Manual DB Corruption)

**Purpose:** Demonstrate that modifying an audit record is detected.

```sql
-- In MySQL:
USE adaptive_auth;

-- Tamper with one record
UPDATE auth_events
SET event_type = 'LOGOUT'
WHERE id = (SELECT MIN(id) FROM (SELECT id FROM auth_events WHERE user_id = 3) t);
```

Now re-run the audit:

```bash
curl -s "http://localhost:8000/api/risk/audit?user_id=<MFA_USER_ID>" \
  | python -m json.tool
```

**Expected — Tamper detected:**
```json
{
  "valid": false,
  "events_checked": 4,
  "broken_at_event_id": 12
}
```

**Pass Criteria:** `valid` is `false` and the tampered `event_id` is identified precisely.

> **Restore:** `UPDATE auth_events SET event_type = 'LOGIN' WHERE id = <tampered_id>;`

---

## 10. Module 8 — JWT Security & Token Revocation

### TEST-026 — JWT Payload Contains Security Claims

Login and decode the access token at `https://jwt.io`:

```bash
curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "mfauser", "password": "Mfa@Test99"}' \
  | python -m json.tool
```

Decode the `access_token` payload — it must contain:

```json
{
  "sub": "mfauser",
  "user_id": 3,
  "type": "access",
  "device": "a3f2b9c1d4...",
  "jti": "550e8400-e29b-...",
  "session_id": "f47ac10b-...",
  "iat": 1709890800,
  "exp": 1709892600
}
```

**Pass Criteria:** `jti`, `device`, `session_id`, and `type` claims present.

---

### TEST-027 — Logout Revokes Access Token

```bash
TK_LOGIN=$(curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "mfauser", "password": "Mfa@Test99"}')

TK_ACCESS=$(echo $TK_LOGIN | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Logout
curl -s -X POST http://localhost:8000/api/logout \
  -H "Content-Type: application/json" \
  -d "{\"access_token\": \"$TK_ACCESS\"}" \
  | python -m json.tool
```

**Expected (HTTP 200):**
```json
{
  "message": "Logged out successfully"
}
```

---

### TEST-028 — Revoked Token Is Rejected

Attempt to use the same token again:

```bash
curl -s -X POST http://localhost:8000/api/logout \
  -H "Content-Type: application/json" \
  -d "{\"access_token\": \"$TK_ACCESS\"}" \
  | python -m json.tool
```

**Expected (HTTP 401):**
```json
{
  "detail": "Token has been revoked"
}
```

**Verify in MySQL:**
```sql
SELECT jti, user_id, revoked_at, reason
FROM revoked_tokens
ORDER BY revoked_at DESC LIMIT 3;
```

**Pass Criteria:** Token blacklisted immediately — not just expiry-based. JTI stored in Redis AND `revoked_tokens` table.

---

## 11. Module 9 — Security Headers

### TEST-029 — HTTP Security Headers Verification

```bash
curl -s -I http://localhost:8000/health
```

**Expected Headers (all must be present):**

| Header | Expected Value |
|--------|---------------|
| `x-content-type-options` | `nosniff` |
| `x-frame-options` | `DENY` |
| `x-xss-protection` | `1; mode=block` |
| `referrer-policy` | `strict-origin-when-cross-origin` |
| `permissions-policy` | `geolocation=(), microphone=(), camera=()` |
| `content-security-policy` | Contains `default-src 'self'` |

Verify with grep:
```bash
curl -s -I http://localhost:8000/health | grep -Ei "x-content|x-frame|x-xss|referrer|permissions|content-security"
```

**What each header defends against:**

| Header | Threat Mitigated |
|--------|-----------------|
| `X-Content-Type-Options` | MIME-type sniffing |
| `X-Frame-Options: DENY` | Clickjacking |
| `X-XSS-Protection` | Reflected XSS (legacy browsers) |
| `Referrer-Policy` | Sensitive URL leakage |
| `Permissions-Policy` | Unauthorized device API access |
| `Content-Security-Policy` | Script injection, data exfiltration |

> `Strict-Transport-Security` only appears when `ENVIRONMENT=production` in `.env`.

---

## 12. Module 10 — Rate Limiting

### TEST-030 — Login Rate Limit (10 requests/minute)

Send 11 login attempts rapidly:

```bash
for i in $(seq 1 11); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8000/api/login \
    -H "Content-Type: application/json" \
    -d '{"username": "ratetest", "password": "Any@Pass1"}')
  echo "Request $i: HTTP $STATUS"
done
```

**Expected:**
- Requests 1–10: `HTTP 401` (wrong credentials, not rate-limited)
- Request 11: `HTTP 429 Too Many Requests`

---

### TEST-031 — Register Rate Limit (5 requests/minute)

```bash
for i in $(seq 1 6); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8000/api/register \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"rateuser$i\", \"password\": \"Rate@Pass${i}!\"}")
  echo "Request $i: HTTP $STATUS"
done
```

**Expected:**
- Requests 1–5: `HTTP 201`
- Request 6: `HTTP 429 Too Many Requests`

---

## 13. Automated Attack Simulation

The project includes a complete attack simulation script:

```
tests/simulate_attacks.py
```

### Prerequisites

```bash
pip install httpx   # already in requirements.txt
```

### Run All Scenarios

```bash
py tests/simulate_attacks.py
```

### Run Individual Scenarios

```bash
py tests/simulate_attacks.py --scenario 1   # Legitimate login
py tests/simulate_attacks.py --scenario 2   # MFA Fatigue Attack
py tests/simulate_attacks.py --scenario 3   # Brute-Force Attack
py tests/simulate_attacks.py --base-url http://192.168.1.10:8000   # Custom host
```

### Expected Terminal Output

```
Adaptive Auth System — Attack Simulator
Target: http://localhost:8000
  [PASS] Server is up: {'status': 'ok', 'version': '2.0.0', ...}

============================================================
  SCENARIO 1 — Legitimate Login
============================================================
  [PASS] Registered user 'legit_a3f8c1'
  [PASS] Login OK — user_id=12 session=4a9e7b2c...
  [INFO] MFA challenge issued — challenge_id=81d3f2a0...
  [PASS] MFA APPROVED → decision=ALLOW score=0 signals=[]
  [PASS] Legitimate login completed with ALLOW decision
  [PASS] Risk eval — score=0 decision=ALLOW signals=[]

  Final score: 0 → ALLOW

============================================================
  SCENARIO 2 — MFA Fatigue Attack
  Attacker has stolen credentials and spams MFA pushes
============================================================
  [PASS] Registered user 'victim_b9c4d7'
  [PASS] Login OK — user_id=13 session=9f1a3e6d...
  [INFO] Phase 1 — Sending 5 rapid MFA push requests...
  [INFO] MFA challenge issued — challenge_id=c7a2e901...
  [INFO] MFA challenge issued — challenge_id=d4b8f230...
  [INFO] MFA challenge issued — challenge_id=e5c9a341...
  [INFO] MFA challenge issued — challenge_id=f6d0b452...
  [INFO] MFA challenge issued — challenge_id=a7e1c563...
  [INFO] Phase 2 — Victim approves 4 MFA pushes under fatigue...
  [PASS] MFA APPROVED → decision=ALLOW score=0 signals=[]
  [PASS] MFA APPROVED → decision=ALLOW score=30 signals=['excess_mfa_requests']
  [WARN] Risk escalation detected at approval #2
  [WARN] MFA APPROVED → decision=VERIFY score=55 signals=['excess_mfa_requests', 'repeated_approvals']
  [WARN] Risk escalation detected at approval #3
  [WARN] MFA APPROVED → decision=VERIFY score=55 signals=['excess_mfa_requests', 'repeated_approvals']
  [WARN] Risk escalation detected at approval #4
  [INFO] Phase 3 — Running explicit risk evaluation...
  [WARN] Risk eval — score=55 decision=VERIFY signals=['excess_mfa_requests', 'repeated_approvals']

  Final score: 55 → VERIFY
  [PASS] Attack DETECTED correctly

============================================================
  SCENARIO 3 — Brute-Force Login Attack
  Attacker tries wrong passwords until account locks
============================================================
  [PASS] Registered user 'bruteforced_e3f7a9'
  [INFO] Sending 6 failed login attempts with wrong password...
  [INFO] Attempt 1: rejected (401)
  [INFO] Attempt 2: rejected (401)
  [INFO] Attempt 3: rejected (401)
  [INFO] Attempt 4: rejected (401)
  [PASS] Account locked after 5 attempts
  [PASS] Correct credentials also rejected — account lockout confirmed

============================================================
  Simulation complete. Check the dashboard at:
  http://localhost:8000/dashboard
============================================================
```

**Pass Criteria:**
- All `[PASS]` lines appear
- Scenario 2 ends with `Attack DETECTED correctly`
- Scenario 3 ends with `account lockout confirmed`
- No `[FAIL]` lines

---

## 14. Dashboard Visual Testing

### TEST-032 — Dashboard Access and Initial Load

1. Open browser: `http://localhost:8000`
2. Register a user via the UI form
3. Log in — you are redirected to `/dashboard`

**Pass Criteria:**
- NavBar shows username (top-right)
- Risk Score badge shows `--` (not yet evaluated)
- Authentication Events table loads recent events

---

### TEST-033 — Risk Evaluation via Dashboard

1. Click **EVALUATE RISK** in the NavBar

**Expected:**
- Risk Score badge updates (colour-coded ring):
  - Green = ALLOW (0–39)
  - Yellow = VERIFY (40–69)
  - Red = BLOCK (70+)
- Active Signals panel lists each triggered signal with weight
- Risk Score Timeline chart adds a new data point
- Signal Frequency bar chart increments for each triggered signal
- Authentication Events table refreshes

---

### TEST-034 — Audit Chain Verification via Dashboard

1. Click **VERIFY CHAIN**

**Expected — Intact chain:**
```
✓ CHAIN INTACT
7 events verified.
```

**Expected — After DB tampering (TEST-025):**
```
✗ CHAIN BROKEN
Tampered at event_id=12
7 events checked.
```

**After running MFA fatigue simulation:**
- Attack Detection Log panel shows colour-coded entries
- `[VERIFY]` entries appear in yellow
- `[BLOCK]` entries appear in red
- Attack count badge increments accordingly

---

## 15. Database Verification (SQL)

Connect to MySQL and run these verification queries:

```sql
USE adaptive_auth;

-- Verify all 7 tables exist
SHOW TABLES;
-- Expected: auth_events, login_sessions, mfa_challenges,
--           revoked_tokens, risk_decisions, trusted_devices, users

-- Confirm bcrypt hashing (prefix must be $2b$)
SELECT id, username, LEFT(password_hash, 7) AS hash_prefix,
       failed_login_attempts, locked_until
FROM users;

-- Audit chain (each row should have a unique 64-char SHA-256 hash)
SELECT id, event_type, success, ip_address,
       LEFT(chain_hash, 16) AS hash_start,
       created_at
FROM auth_events
ORDER BY id ASC
LIMIT 10;

-- Active MFA challenges (unused and not expired)
SELECT challenge_id, user_id, expires_at, used
FROM mfa_challenges
WHERE used = 0 AND expires_at > NOW();

-- Token revocation log
SELECT jti, user_id, revoked_at, reason
FROM revoked_tokens
ORDER BY revoked_at DESC
LIMIT 5;

-- Risk decision history
SELECT user_id, risk_score, decision, reason, created_at
FROM risk_decisions
ORDER BY created_at DESC
LIMIT 10;

-- Login sessions
SELECT session_id, user_id, ip_address, is_active, terminated_reason
FROM login_sessions
ORDER BY created_at DESC
LIMIT 5;

-- Signal frequency analysis
SELECT event_type, COUNT(*) AS count
FROM auth_events
GROUP BY event_type
ORDER BY count DESC;
```

---

## 16. Risk Score Reference Table

### Signal Weights

| Signal | Variable | Weight | Trigger Condition |
|--------|----------|--------|--------------------|
| Excess MFA requests | `excess_mfa_requests` | **+30** | >3 MFA requests in 120 seconds |
| Rapid login attempts | `rapid_login_attempts` | **+20** | >5 login attempts in 300 seconds |
| Repeated approvals | `repeated_approvals` | **+25** | >3 MFA approvals in 120 seconds |
| New device detected | `new_device_detected` | **+20** | Fingerprint not in trusted list |
| IP address change | `ip_change_detected` | **+15** | IP differs from last recorded login |
| Impossible travel | `impossible_travel` | **+40** | Multiple distinct IPs in same session |
| Off-hours access | `off_hours_access` | **+10** | Access between 22:00–06:00 UTC |
| **Maximum possible** | | **160** | All 7 signals simultaneously |

### Decision Thresholds

| Score Range | Decision | Action |
|-------------|----------|--------|
| 0 – 39 | **ALLOW** | Session continues normally |
| 40 – 69 | **VERIFY** | Step-up authentication recommended |
| 70 – 160 | **BLOCK** | Session terminated |

### Common Attack Scenarios

| Scenario | Signals | Score | Decision |
|----------|---------|-------|----------|
| Clean login | none | 0 | ALLOW |
| New device on familiar IP | new_device | 20 | ALLOW |
| New device + IP change | new_device + ip_change | 35 | ALLOW |
| MFA fatigue (4 pushes + 3 approvals) | excess_mfa + repeated_approvals | 55 | VERIFY |
| Impossible travel only | impossible_travel | 40 | VERIFY |
| MFA fatigue + IP change | excess_mfa + repeated_approvals + ip_change | 70 | BLOCK |
| All 7 signals | all | 160 | BLOCK |

### Industry Standards Reference

| Component | Standard | Relevance |
|-----------|----------|-----------|
| bcrypt ($2b$12$) | NIST SP 800-63B | Password storage |
| Account lockout (5 fails) | OWASP ASVS 2.1.7 | Brute-force protection |
| MFA challenge UUID | RFC 4122 | Anti-replay token |
| JWT with jti revocation | RFC 7519 §4.1.7 | Token lifecycle |
| Rate limiting | OWASP API Security Top 10 #4 | API abuse prevention |
| Device fingerprinting | NIST SP 800-63B §7.1 | Session binding |
| Hash chain audit log | NIST SP 800-92 | Tamper-evident logging |
| Risk scoring engine | NIST SP 800-30 | Quantitative risk |
| Impossible travel detection | Banking fraud standards | Geo-anomaly detection |
| Behaviour monitoring (UEBA) | Gartner UEBA | User behaviour analytics |
| Structured JSON logs | ISO 27001 / SOC 2 | Compliance audit trail |
| Secure HTTP headers | OWASP ASVS 14.4 | Browser security |

---

## 17. Complete API Reference Card

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | None | Liveness probe |
| `GET` | `/docs` | None | Swagger UI |
| `GET` | `/redoc` | None | ReDoc reference |
| `POST` | `/api/register` | None | Register new user |
| `POST` | `/api/login` | None | Authenticate, get JWT pair + session |
| `POST` | `/api/logout` | Token | Revoke access token, end session |
| `POST` | `/api/refresh` | Token | Rotate access + refresh tokens |
| `POST` | `/api/mfa/request` | Query (user_id + session_id) | Issue MFA challenge |
| `POST` | `/api/mfa/respond` | Body (user_id + challenge_id) | Approve or deny challenge |
| `GET` | `/api/risk/evaluate` | Query (user_id) | Run risk analysis |
| `GET` | `/api/risk/audit` | Query (user_id) | Verify audit chain |
| `GET` | `/api/logs/events` | Query (user_id) | Auth event history |
| `GET` | `/api/logs/decisions` | Query (user_id) | Risk decision history |
| `GET` | `/api/logs/sessions` | Query (user_id) | Session history |
| `GET` | `/api/logs/devices` | Query (user_id) | Trusted devices list |

### Quick cURL Reference

```bash
# Register
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "demo", "password": "Demo@Pass1"}'

# Login
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "demo", "password": "Demo@Pass1"}'

# Request MFA challenge
curl -X POST "http://localhost:8000/api/mfa/request?user_id=1&session_id=<sid>"

# Respond to MFA challenge
curl -X POST http://localhost:8000/api/mfa/respond \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "challenge_id": "<cid>", "approved": true}'

# Evaluate risk
curl "http://localhost:8000/api/risk/evaluate?user_id=1"

# Verify audit chain
curl "http://localhost:8000/api/risk/audit?user_id=1"

# View events log
curl "http://localhost:8000/api/logs/events?user_id=1&limit=10"

# Logout
curl -X POST http://localhost:8000/api/logout \
  -H "Content-Type: application/json" \
  -d '{"access_token": "<token>"}'
```

---

## Test Coverage Summary

| Module | Tests | Key Feature Validated |
|--------|-------|-----------------------|
| Health | TEST-001, 002 | Server up, docs accessible |
| Registration | TEST-003 – 007 | 4 password policy rules enforced |
| Authentication | TEST-008 – 011 | Login + lockout working |
| MFA lifecycle | TEST-012 – 016 | Issue/approve/deny/replay/invalid |
| Risk engine | TEST-017, 018 | Zero score for clean user |
| MFA fatigue | TEST-019 – 021 | VERIFY/BLOCK on attack pattern |
| Brute force | TEST-022, 023 | Lockout after 5 failures |
| Audit chain | TEST-024, 025 | Integrity + tamper detection |
| JWT security | TEST-026 – 028 | Claims present, revocation works |
| Sec headers | TEST-029 | All 6 headers present |
| Rate limiting | TEST-030, 031 | 429 after configured limit |
| Automation | Simulation script | All scenarios pass |
| Dashboard | TEST-032 – 034 | Charts, risk badge, chain verify |
| Database | SQL queries | All 7 tables, correct data |

**Total: 34 test cases across 10 security modules + automated simulation + dashboard + SQL verification.**

---

*Adaptive Auth System v2 — Testing Guide*
*For academic, professional, and security audit use.*
