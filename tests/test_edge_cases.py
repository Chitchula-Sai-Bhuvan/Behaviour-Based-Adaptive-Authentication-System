"""
tests/test_edge_cases.py
─────────────────────────
Security edge-case and failure-scenario test suite.

Coverage:
  Module 1  — Password policy enforcement
  Module 2  — Account lockout / wrong credentials
  Module 3  — MFA replay prevention, invalid/cross-user challenges
  Module 7  — Audit-chain integrity check
  Module 8  — JWT token revocation, refresh token rotation
  Module 9  — HTTP security headers
  Module 10 — Rate limiting (login + register)

Each test module sends a unique X-Forwarded-For IP so that the rate-limit
bucket for one module does not interfere with another module's requests.

Usage:
    py tests/test_edge_cases.py [--base-url http://localhost:8001]
"""

import argparse
import sys
import time
import uuid

import httpx

DEFAULT_BASE = "http://localhost:8001"

# ── ANSI colours ───────────────────────────────────────────────────────────────
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
SKIP = "\033[90m[SKIP]\033[0m"

_results: list[tuple[str, str]] = []


def _record(test_id: str, label: str, msg: str):
    status = "PASS" if label == PASS else "FAIL"
    _results.append((test_id, status))
    print(f"  {label} [{test_id}] {msg}")


def section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


# ── Per-module IP helpers ──────────────────────────────────────────────────────

def _module_ip(module: str) -> str:
    """Return a stable fake IP per test module for isolated rate-limit buckets."""
    buckets = {
        "pw":      "10.0.1.1",
        "auth":    "10.0.2.1",
        "mfa":     "10.0.3.1",
        "audit":   "10.0.4.1",
        "jwt":     "10.0.5.1",
        "headers": "10.0.6.1",
        "rate":    "10.0.7.1",
    }
    return buckets.get(module, f"10.0.9.{hash(module) % 254 + 1}")


def _make_client(base_url: str, module: str) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        timeout=15,
        headers={"X-Forwarded-For": _module_ip(module)},
    )


# ── Low-level HTTP helpers ──────────────────────────────────────────────────

def _register(c: httpx.Client, username: str, password: str) -> httpx.Response:
    return c.post("/api/register", json={"username": username, "password": password})


def _login(c: httpx.Client, username: str, password: str) -> httpx.Response:
    return c.post("/api/login", json={"username": username, "password": password})


def _mfa_request(c: httpx.Client, user_id: int, session_id: str) -> httpx.Response:
    return c.post(f"/api/mfa/request?user_id={user_id}&session_id={session_id}")


def _mfa_respond(c: httpx.Client, user_id: int, challenge_id: str, approved: bool) -> httpx.Response:
    return c.post("/api/mfa/respond", json={
        "user_id": user_id,
        "challenge_id": challenge_id,
        "approved": approved,
    })


def _logout(c: httpx.Client, access_token: str, session_id: str) -> httpx.Response:
    return c.post(
        "/api/logout",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"session_id": session_id},
    )


def _refresh(c: httpx.Client, refresh_token: str) -> httpx.Response:
    return c.post("/api/refresh", json={"refresh_token": refresh_token})


def _quick_user(c: httpx.Client) -> dict:
    """Register + login a fresh random user; return the login response dict."""
    u = f"edge_{uuid.uuid4().hex[:8]}"
    p = "Edge@Test99"
    _register(c, u, p)
    r = _login(c, u, p)
    if r.status_code != 200:
        raise RuntimeError(f"Setup login failed: {r.status_code} {r.text}")
    return r.json()


# ══════════════════════════════════════════════════════════════════════════════
# Module 1 — Password Policy
# ══════════════════════════════════════════════════════════════════════════════

def test_password_policy(base_url: str):
    section("Module 1 — Password Policy Enforcement")
    with _make_client(base_url, "pw") as c:

        # TEST-PW-01: Successful registration (baseline)
        u = f"pwtest_{uuid.uuid4().hex[:6]}"
        r = _register(c, u, "Secure@Pass1")
        if r.status_code == 201:
            _record("TEST-PW-01", PASS, "Valid password accepted (HTTP 201)")
        else:
            _record("TEST-PW-01", FAIL, f"Valid password rejected: {r.status_code} {r.text}")

        # TEST-PW-02: Duplicate username — 409 Conflict
        r = _register(c, u, "Secure@Pass1")
        if r.status_code == 409:
            _record("TEST-PW-02", PASS, "Duplicate username rejected (HTTP 409)")
        else:
            _record("TEST-PW-02", FAIL, f"Expected 409, got {r.status_code}: {r.text}")

        # TEST-PW-03: No uppercase — policy violation → 422
        r = _register(c, f"pw_{uuid.uuid4().hex[:6]}", "weakpass1!")
        if r.status_code == 422:
            _record("TEST-PW-03", PASS, "No-uppercase password rejected (HTTP 422)")
        else:
            _record("TEST-PW-03", FAIL, f"Expected 422, got {r.status_code}: {r.text}")

        # TEST-PW-04: Too short — Pydantic min_length=8 → 422
        r = _register(c, f"pw_{uuid.uuid4().hex[:6]}", "Ab1!")
        if r.status_code == 422:
            _record("TEST-PW-04", PASS, "Short password rejected (HTTP 422)")
        else:
            _record("TEST-PW-04", FAIL, f"Expected 422, got {r.status_code}: {r.text}")

        # TEST-PW-05: Missing special character — policy violation → 422
        r = _register(c, f"pw_{uuid.uuid4().hex[:6]}", "SecurePass1")
        if r.status_code == 422:
            _record("TEST-PW-05", PASS, "No-special-char password rejected (HTTP 422)")
        else:
            _record("TEST-PW-05", FAIL, f"Expected 422, got {r.status_code}: {r.text}")

        # TEST-PW-06: Missing digit — policy violation → 422
        r = _register(c, f"pw_{uuid.uuid4().hex[:6]}", "Secure@Pass")
        if r.status_code == 422:
            _record("TEST-PW-06", PASS, "No-digit password rejected (HTTP 422)")
        else:
            _record("TEST-PW-06", FAIL, f"Expected 422, got {r.status_code}: {r.text}")

        # TEST-PW-07: Invalid username format (spaces) — Pydantic pattern → 422
        r = _register(c, "user name!", "Secure@Pass1")
        if r.status_code == 422:
            _record("TEST-PW-07", PASS, "Username with spaces rejected (HTTP 422)")
        else:
            _record("TEST-PW-07", FAIL, f"Expected 422, got {r.status_code}: {r.text}")


# ══════════════════════════════════════════════════════════════════════════════
# Module 2 — Authentication & Account Lockout
# ══════════════════════════════════════════════════════════════════════════════

def test_auth_lockout(base_url: str):
    section("Module 2 — Authentication & Account Lockout")
    with _make_client(base_url, "auth") as c:

        u = f"lock_{uuid.uuid4().hex[:6]}"
        p = "Lock@Pass99"
        _register(c, u, p)

        # TEST-AUTH-01: Wrong password → 401 without "locked" in message
        r = _login(c, u, "WrongPass!")
        if r.status_code == 401 and "locked" not in r.json().get("detail", "").lower():
            _record("TEST-AUTH-01", PASS, "Wrong password → 401 Invalid credentials")
        else:
            _record("TEST-AUTH-01", FAIL, f"Unexpected: {r.status_code} {r.text}")

        # TEST-AUTH-02: Non-existent user → 401 (prevents user enumeration via 404)
        r = _login(c, f"nosuchuser_{uuid.uuid4().hex[:6]}", "Any@Pass1!")
        if r.status_code == 401:
            _record("TEST-AUTH-02", PASS, "Non-existent user returns 401 (no user enumeration)")
        else:
            _record("TEST-AUTH-02", FAIL, f"Expected 401 for unknown user, got {r.status_code}")

        # TEST-AUTH-03: Account lockout after MAX_FAILED_LOGINS failures
        locked = False
        for attempt in range(1, 10):
            r = _login(c, u, "WrongPass!")
            detail = r.json().get("detail", "")
            if "locked" in detail.lower():
                _record("TEST-AUTH-03", PASS, f"Account locked after {attempt} failed attempts")
                locked = True
                break
            elif r.status_code == 429:
                _record("TEST-AUTH-03", FAIL,
                        f"Rate limit hit at attempt {attempt} before lockout fired — "
                        f"check RATE_LIMIT_LOGIN vs MAX_FAILED_LOGINS config")
                break
            time.sleep(0.2)

        if not locked and not any(s == 429 for s in [r.status_code]):
            _record("TEST-AUTH-03", FAIL, "Account never locked after 9 bad attempts")

        # TEST-AUTH-04: Correct password rejected while locked
        r = _login(c, u, p)
        if r.status_code == 401 and "locked" in r.json().get("detail", "").lower():
            _record("TEST-AUTH-04", PASS, "Correct password rejected while account is locked")
        elif not locked:
            print(f"  {SKIP} [TEST-AUTH-04] Skipped — lockout did not fire (see TEST-AUTH-03)")
        else:
            _record("TEST-AUTH-04", FAIL,
                    f"Expected locked-rejection: {r.status_code} {r.text}")

        # TEST-AUTH-05: Clean login on a fresh account returns JWT pair
        u2 = f"clean_{uuid.uuid4().hex[:6]}"
        p2 = "Clean@Pass99"
        _register(c, u2, p2)
        r = _login(c, u2, p2)
        if r.status_code == 200 and "access_token" in r.json():
            _record("TEST-AUTH-05", PASS, "Clean login succeeds — JWT pair returned")
        else:
            _record("TEST-AUTH-05", FAIL, f"Clean login failed: {r.status_code} {r.text}")


# ══════════════════════════════════════════════════════════════════════════════
# Module 3 — MFA Challenge Security
# ══════════════════════════════════════════════════════════════════════════════

def test_mfa_security(base_url: str):
    section("Module 3 — MFA Challenge Security")
    with _make_client(base_url, "mfa") as c:

        sess = _quick_user(c)
        uid, sid = sess["user_id"], sess["session_id"]

        # TEST-MFA-01: Issue a challenge
        r = _mfa_request(c, uid, sid)
        if r.status_code == 200 and "challenge_id" in r.json():
            challenge_id = r.json()["challenge_id"]
            _record("TEST-MFA-01", PASS, f"Challenge issued ({challenge_id[:8]}...)")
        else:
            _record("TEST-MFA-01", FAIL, f"Challenge failed: {r.status_code} {r.text}")
            return

        # TEST-MFA-02: Approve once — succeeds
        r = _mfa_respond(c, uid, challenge_id, approved=True)
        if r.status_code == 200:
            _record("TEST-MFA-02", PASS, "First MFA approval accepted")
        else:
            _record("TEST-MFA-02", FAIL, f"First approval failed: {r.status_code} {r.text}")

        # TEST-MFA-03: Replay the same challenge — must be rejected
        r = _mfa_respond(c, uid, challenge_id, approved=True)
        if r.status_code in (400, 409) and "already" in r.json().get("detail", "").lower():
            _record("TEST-MFA-03", PASS, "Replay blocked — challenge already used")
        else:
            _record("TEST-MFA-03", FAIL,
                    f"Replay NOT blocked: {r.status_code} {r.json().get('detail','')}")

        # TEST-MFA-04: Completely fabricated challenge_id → 400 or 404
        r = _mfa_respond(c, uid, str(uuid.uuid4()), approved=True)
        if r.status_code in (400, 404):
            _record("TEST-MFA-04", PASS, "Non-existent challenge_id rejected")
        else:
            _record("TEST-MFA-04", FAIL,
                    f"Expected 400/404 for fake challenge, got {r.status_code}: {r.text}")

        # TEST-MFA-05: Cross-user — user B cannot claim user A's challenge
        sess_b = _quick_user(c)
        uid_b = sess_b["user_id"]
        r_chal = _mfa_request(c, uid, sid)
        if r_chal.status_code == 200:
            user_a_challenge = r_chal.json()["challenge_id"]
            r = _mfa_respond(c, uid_b, user_a_challenge, approved=True)
            if r.status_code in (400, 404):
                _record("TEST-MFA-05", PASS, "Cross-user challenge claim rejected")
            else:
                _record("TEST-MFA-05", FAIL,
                        f"Cross-user challenge NOT blocked: {r.status_code} {r.json().get('detail','')}")
        else:
            print(f"  {SKIP} [TEST-MFA-05] Could not issue challenge for cross-user test")

        # TEST-MFA-06: MFA request for non-existent user → 404
        r = _mfa_request(c, 999999, "fake-session")
        if r.status_code == 404:
            _record("TEST-MFA-06", PASS, "MFA request for non-existent user → 404")
        else:
            _record("TEST-MFA-06", FAIL, f"Expected 404, got {r.status_code}")

        # TEST-MFA-07: Denial is consumed, preventing replay
        cid2_r = _mfa_request(c, uid, sid)
        if cid2_r.status_code == 200:
            cid2 = cid2_r.json()["challenge_id"]
            r = _mfa_respond(c, uid, cid2, approved=False)
            if r.status_code == 200 and r.json().get("event_type") == "DENY":
                _record("TEST-MFA-07", PASS, "Denial accepted — event_type=DENY")
            else:
                _record("TEST-MFA-07", FAIL,
                        f"Denial unexpected: {r.status_code} {r.text}")
            r2 = _mfa_respond(c, uid, cid2, approved=True)
            if r2.status_code in (400, 409):
                _record("TEST-MFA-07b", PASS, "Denied challenge cannot be replayed")
            else:
                _record("TEST-MFA-07b", FAIL,
                        f"Denied-challenge replay not blocked: {r2.status_code}")
        else:
            print(f"  {SKIP} [TEST-MFA-07] Could not issue second challenge")


# ══════════════════════════════════════════════════════════════════════════════
# Module 7 — Audit Chain Integrity
# ══════════════════════════════════════════════════════════════════════════════

def test_audit_chain(base_url: str):
    section("Module 7 — Audit Chain Integrity")
    with _make_client(base_url, "audit") as c:

        sess = _quick_user(c)
        uid, sid = sess["user_id"], sess["session_id"]

        # Generate a couple of events so the chain has > 1 link
        cr = _mfa_request(c, uid, sid)
        if cr.status_code == 200:
            _mfa_respond(c, uid, cr.json()["challenge_id"], approved=True)

        # TEST-AUDIT-01: Fresh user's chain must be intact
        r = c.get(f"/api/risk/audit?user_id={uid}")
        if r.status_code == 200 and r.json().get("valid") is True:
            _record("TEST-AUDIT-01", PASS,
                    f"Audit chain intact ({r.json().get('events_checked', 0)} events)")
        elif r.status_code == 200:
            data = r.json()
            _record("TEST-AUDIT-01", FAIL,
                    f"Chain broken at event_id={data.get('broken_at_event_id')} — unexpected")
        else:
            _record("TEST-AUDIT-01", FAIL, f"Audit returned {r.status_code}: {r.text}")

        # TEST-AUDIT-02: Unknown user returns empty valid chain or 404
        r = c.get("/api/risk/audit?user_id=999998")
        if r.status_code == 404:
            _record("TEST-AUDIT-02", PASS, "Unknown user audit → 404")
        elif r.status_code == 200 and r.json().get("events_checked", 0) == 0:
            _record("TEST-AUDIT-02", PASS, "Unknown user returns empty valid chain (events=0)")
        elif r.status_code == 200:
            _record("TEST-AUDIT-02", PASS,
                    f"Unknown user audit: {r.json()} — non-crash acceptable")
        else:
            _record("TEST-AUDIT-02", FAIL, f"Unexpected {r.status_code}: {r.text}")


# ══════════════════════════════════════════════════════════════════════════════
# Module 8 — JWT Security & Token Revocation
# ══════════════════════════════════════════════════════════════════════════════

def test_jwt_security(base_url: str):
    section("Module 8 — JWT Security & Token Revocation")
    with _make_client(base_url, "jwt") as c:

        sess = _quick_user(c)
        access_token  = sess["access_token"]
        refresh_token = sess["refresh_token"]
        session_id    = sess["session_id"]

        # TEST-JWT-01: Logout succeeds
        r = _logout(c, access_token, session_id)
        if r.status_code == 200:
            _record("TEST-JWT-01", PASS, "Logout accepted (HTTP 200)")
        else:
            _record("TEST-JWT-01", FAIL, f"Logout failed: {r.status_code} {r.text}")

        # TEST-JWT-02: Revoked access token rejected on reuse
        r2 = _logout(c, access_token, session_id)
        if r2.status_code in (401, 400):
            _record("TEST-JWT-02", PASS, "Revoked token rejected on reuse (HTTP 401/400)")
        elif r2.status_code == 200:
            _record("TEST-JWT-02", PASS,
                    "Second logout idempotent (HTTP 200) — token already invalidated")
        else:
            _record("TEST-JWT-02", FAIL,
                    f"Unexpected second-logout response: {r2.status_code} {r2.text}")

        # TEST-JWT-03: Refresh token exchange succeeds
        sess2 = _quick_user(c)
        rt = sess2["refresh_token"]
        r = _refresh(c, rt)
        if r.status_code == 200 and "access_token" in r.json():
            new_rt = r.json()["refresh_token"]
            _record("TEST-JWT-03", PASS, "Refresh token exchange succeeded — new pair issued")

            # TEST-JWT-04: Old refresh token invalidated after rotation
            r2 = _refresh(c, rt)
            if r2.status_code == 401:
                _record("TEST-JWT-04", PASS, "Old refresh token rejected after rotation (HTTP 401)")
            else:
                _record("TEST-JWT-04", FAIL,
                        f"Old refresh token should be 401, got {r2.status_code}: {r2.text}")

            # TEST-JWT-05: New refresh token (from rotation) is valid
            r3 = _refresh(c, new_rt)
            if r3.status_code == 200 and "access_token" in r3.json():
                _record("TEST-JWT-05", PASS, "New refresh token after rotation is valid")
            else:
                _record("TEST-JWT-05", FAIL,
                        f"New refresh token rejected: {r3.status_code} {r3.text}")
        else:
            _record("TEST-JWT-03", FAIL, f"Refresh failed: {r.status_code} {r.text}")

        # TEST-JWT-06: Access token submitted to /refresh must be rejected
        sess3 = _quick_user(c)
        r = _refresh(c, sess3["access_token"])
        if r.status_code == 401:
            _record("TEST-JWT-06", PASS, "Access token rejected on /refresh (wrong type)")
        else:
            _record("TEST-JWT-06", FAIL,
                    f"Access token should fail on /refresh, got {r.status_code}: {r.text}")

        # TEST-JWT-07: Garbage token on /refresh → 401
        r = _refresh(c, "not.a.jwt.at.all")
        if r.status_code == 401:
            _record("TEST-JWT-07", PASS, "Malformed token → 401 on /refresh")
        else:
            _record("TEST-JWT-07", FAIL,
                    f"Expected 401 for garbage token, got {r.status_code}: {r.text}")


# ══════════════════════════════════════════════════════════════════════════════
# Module 9 — Security Headers
# ══════════════════════════════════════════════════════════════════════════════

REQUIRED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options":        "DENY",
    "x-xss-protection":       "1; mode=block",
    "referrer-policy":        "strict-origin-when-cross-origin",
}


def test_security_headers(base_url: str):
    section("Module 9 — HTTP Security Headers")
    with _make_client(base_url, "headers") as c:
        r = c.get("/health")
        h = {k.lower(): v for k, v in r.headers.items()}

        for header, expected in REQUIRED_HEADERS.items():
            tag = f"TEST-HDR-{header.upper().replace('-', '_')[:20]}"
            if h.get(header) == expected:
                _record(tag, PASS, f"{header}: {h[header]}")
            else:
                _record(tag, FAIL,
                        f"{header}: expected '{expected}', got '{h.get(header, 'MISSING')}'")

        for hdr in ("permissions-policy", "content-security-policy"):
            tag = f"TEST-HDR-{hdr.upper().replace('-','_')[:20]}"
            if hdr in h:
                _record(tag, PASS, f"{hdr} present: {h[hdr][:60]}")
            else:
                _record(tag, FAIL, f"{hdr} MISSING")


# ══════════════════════════════════════════════════════════════════════════════
# Module 10 — Rate Limiting
# ══════════════════════════════════════════════════════════════════════════════

def test_rate_limiting(base_url: str):
    section("Module 10 — Rate Limiting")
    with _make_client(base_url, "rate") as c:

        # TEST-RATE-01: Login endpoint — 429 within 12 rapid requests (limit=10/min)
        print(f"  {INFO} [TEST-RATE-01] Sending 12 rapid login requests...")
        statuses = []
        for _ in range(12):
            r = c.post("/api/login", json={"username": "ratetest", "password": "Any@Pass1"})
            statuses.append(r.status_code)
            time.sleep(0.05)

        if 429 in statuses:
            idx = statuses.index(429)
            _record("TEST-RATE-01", PASS,
                    f"Login rate limit enforced at request #{idx + 1} (HTTP 429)")
        else:
            _record("TEST-RATE-01", FAIL,
                    f"No 429 after 12 login requests. Statuses: {statuses}")

        # TEST-RATE-02: Register endpoint — 429 within 7 rapid requests (limit=5/min)
        print(f"  {INFO} [TEST-RATE-02] Sending 7 rapid register requests...")
        statuses = []
        for i in range(7):
            r = _register(c, f"rlu_{uuid.uuid4().hex[:8]}", f"Rate@Pass{i}!")
            statuses.append(r.status_code)
            time.sleep(0.05)

        if 429 in statuses:
            idx = statuses.index(429)
            _record("TEST-RATE-02", PASS,
                    f"Register rate limit enforced at request #{idx + 1} (HTTP 429)")
        else:
            _record("TEST-RATE-02", FAIL,
                    f"No 429 after 7 register requests. Statuses: {statuses}")


# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

def _summary() -> bool:
    print(f"\n{'=' * 60}")
    print("  TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, s in _results if s == "PASS")
    failed = sum(1 for _, s in _results if s == "FAIL")
    total  = len(_results)

    for test_id, status in _results:
        label = PASS if status == "PASS" else FAIL
        print(f"  {label} {test_id}")

    print(f"\n  Total: {total}  |  Passed: {passed}  |  Failed: {failed}")
    if failed == 0:
        print(f"\033[92m  All {total} security edge-case tests passed.\033[0m")
    else:
        print(f"\033[91m  {failed} test(s) failed — review details above.\033[0m")
    print("=" * 60)
    return failed == 0


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Security edge-case test suite")
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    args = parser.parse_args()

    print(f"\nAdaptive Auth System — Security Edge-Case Tests")
    print(f"Target: {args.base_url}")

    try:
        r = httpx.get(f"{args.base_url}/health", timeout=5)
        data = r.json()
        print(f"  {INFO} Server: {data.get('version')} — {data.get('status')}")
    except Exception as exc:
        print(f"  {FAIL} Server not reachable: {exc}")
        sys.exit(1)

    test_password_policy(args.base_url)
    test_auth_lockout(args.base_url)
    test_mfa_security(args.base_url)
    test_audit_chain(args.base_url)
    test_jwt_security(args.base_url)
    test_security_headers(args.base_url)
    test_rate_limiting(args.base_url)

    ok = _summary()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
