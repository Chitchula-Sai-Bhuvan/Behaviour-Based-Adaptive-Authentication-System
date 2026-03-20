"""
tests/simulate_attacks.py
──────────────────────────
Attack simulation script for the Adaptive Auth System.

Simulates three scenarios against a running server:
  1. Legitimate login      — normal flow, should produce ALLOW
  2. MFA fatigue attack    — rapid MFA requests + approvals → VERIFY/BLOCK
  3. Brute-force login     — repeated failed logins → account lockout

Usage:
    # Make sure the server is running on port 8000, then:
    py tests/simulate_attacks.py

    # Target a different host:
    py tests/simulate_attacks.py --base-url http://192.168.1.10:8000
"""

import argparse
import json
import sys
import time
import uuid
import httpx

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_BASE = "http://localhost:8000"

DIVIDER  = "=" * 60
PASS     = "\033[92m[PASS]\033[0m"
FAIL     = "\033[91m[FAIL]\033[0m"
INFO     = "\033[94m[INFO]\033[0m"
WARN     = "\033[93m[WARN]\033[0m"


def _print(label: str, msg: str, data: dict = None):
    suffix = f"  {json.dumps(data)}" if data else ""
    print(f"  {label} {msg}{suffix}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def register(client: httpx.Client, username: str, password: str) -> dict | None:
    r = client.post("/api/register", json={"username": username, "password": password})
    if r.status_code == 201:
        _print(PASS, f"Registered user {username!r}")
        return r.json()
    if r.status_code == 409:
        _print(INFO, f"User {username!r} already exists — using existing account")
        return None   # caller will login instead
    _print(FAIL, f"Register failed: {r.status_code} {r.text}")
    return None


def login(client: httpx.Client, username: str, password: str) -> dict | None:
    r = client.post("/api/login", json={"username": username, "password": password})
    if r.status_code == 200:
        d = r.json()
        _print(PASS, f"Login OK — user_id={d['user_id']} session={d['session_id'][:8]}...")
        return d
    _print(FAIL, f"Login failed: {r.status_code} {r.json().get('detail','')}")
    return None


def request_mfa(client: httpx.Client, user_id: int, session_id: str) -> str | None:
    r = client.post(f"/api/mfa/request?user_id={user_id}&session_id={session_id}")
    if r.status_code == 200:
        d = r.json()
        _print(INFO, f"MFA challenge issued — challenge_id={d['challenge_id'][:8]}...")
        return d["challenge_id"]
    _print(WARN, f"MFA request returned: {r.status_code} {r.json().get('detail','')}")
    return None


def respond_mfa(client: httpx.Client, user_id: int, challenge_id: str, approved: bool) -> dict | None:
    r = client.post("/api/mfa/respond", json={
        "user_id": user_id,
        "challenge_id": challenge_id,
        "approved": approved,
    })
    if r.status_code == 200:
        d = r.json()
        label = PASS if d["risk_decision"] == "ALLOW" else WARN
        _print(label,
               f"MFA {'APPROVED' if approved else 'DENIED'} → "
               f"decision={d['risk_decision']} score={d['risk_score']} "
               f"signals={d['triggered_signals']}")
        return d
    _print(FAIL, f"MFA respond: {r.status_code} {r.json().get('detail','')}")
    return None


def evaluate(client: httpx.Client, user_id: int) -> dict | None:
    r = client.get(f"/api/risk/evaluate?user_id={user_id}")
    if r.status_code == 200:
        d = r.json()
        label = PASS if d["decision"] == "ALLOW" else (WARN if d["decision"] == "VERIFY" else FAIL)
        _print(label, f"Risk eval — score={d['risk_score']} decision={d['decision']} "
                      f"signals={d['triggered_signals']}")
        return d
    return None


# ── Scenario 1: Legitimate Login ───────────────────────────────────────────────

def scenario_legitimate(base_url: str):
    print(f"\n{DIVIDER}")
    print("  SCENARIO 1 — Legitimate Login")
    print(DIVIDER)
    username = f"legit_{uuid.uuid4().hex[:6]}"
    password = "Secure@Pass1"

    with httpx.Client(base_url=base_url, timeout=10) as c:
        register(c, username, password)
        session = login(c, username, password)
        if not session:
            _print(FAIL, "Cannot continue without session"); return

        uid = session["user_id"]
        sid = session["session_id"]

        cid = request_mfa(c, uid, sid)
        if cid:
            result = respond_mfa(c, uid, cid, approved=True)
            if result and result["risk_decision"] == "ALLOW":
                _print(PASS, "Legitimate login completed with ALLOW decision")
            else:
                _print(WARN, f"Unexpected decision: {result}")

        ev = evaluate(c, uid)
        print(f"\n  Final score: {ev['risk_score']} → {ev['decision']}")


# ── Scenario 2: MFA Fatigue Attack ────────────────────────────────────────────

def scenario_mfa_fatigue(base_url: str):
    print(f"\n{DIVIDER}")
    print("  SCENARIO 2 — MFA Fatigue Attack")
    print("  Attacker has stolen credentials and spams MFA pushes")
    print(DIVIDER)
    username = f"victim_{uuid.uuid4().hex[:6]}"
    password = "Target@Pass1"

    with httpx.Client(base_url=base_url, timeout=10) as c:
        register(c, username, password)
        session = login(c, username, password)
        if not session:
            _print(FAIL, "Cannot continue"); return

        uid = session["user_id"]
        sid = session["session_id"]

        # Phase 1: Attacker sends 5 rapid MFA pushes
        _print(INFO, "Phase 1 — Sending 5 rapid MFA push requests...")
        challenges = []
        for i in range(5):
            cid = request_mfa(c, uid, sid)
            if cid:
                challenges.append(cid)
            time.sleep(0.1)   # rapid fire

        # Phase 2: Victim approves 4 times under pressure
        _print(INFO, "Phase 2 — Victim approves 4 MFA pushes under fatigue...")
        for i, cid in enumerate(challenges[:4]):
            result = respond_mfa(c, uid, cid, approved=True)
            if result and result["risk_decision"] in ("VERIFY", "BLOCK"):
                _print(WARN, f"Risk escalation detected at approval #{i+1}")
            time.sleep(0.1)

        # Final evaluation
        _print(INFO, "Phase 3 — Running explicit risk evaluation...")
        ev = evaluate(c, uid)
        if ev:
            print(f"\n  Final score: {ev['risk_score']} → {ev['decision']}")
            if ev["decision"] in ("VERIFY", "BLOCK"):
                _print(PASS, "Attack DETECTED correctly")
            else:
                _print(WARN, "Attack not elevated to VERIFY/BLOCK yet; try more approvals")


# ── Scenario 3: Brute-Force Login ─────────────────────────────────────────────

def scenario_brute_force(base_url: str):
    print(f"\n{DIVIDER}")
    print("  SCENARIO 3 — Brute-Force Login Attack")
    print("  Attacker tries wrong passwords until account locks")
    print(DIVIDER)
    username = f"bruteforced_{uuid.uuid4().hex[:6]}"
    password = "Real@Pass99"

    with httpx.Client(base_url=base_url, timeout=10) as c:
        register(c, username, password)

        _print(INFO, "Sending 6 failed login attempts with wrong password...")
        locked = False
        for attempt in range(1, 8):
            r = c.post("/api/login", json={"username": username, "password": "WrongPass!"})
            detail = r.json().get("detail", "")
            if "locked" in detail.lower():
                _print(PASS, f"Account locked after {attempt} attempts")
                locked = True
                break
            elif r.status_code == 401:
                _print(INFO, f"Attempt {attempt}: rejected (401)")
            time.sleep(0.1)

        if not locked:
            _print(WARN, "Account was not locked — check MAX_FAILED_LOGINS setting")

        # Verify account is locked
        r = c.post("/api/login", json={"username": username, "password": password})
        if r.status_code == 401:
            _print(PASS, "Correct credentials also rejected — account lockout confirmed")
        else:
            _print(FAIL, "Correct credentials accepted despite lockout — check config")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Adaptive Auth attack simulation")
    parser.add_argument("--base-url", default=DEFAULT_BASE, help=f"Base URL (default: {DEFAULT_BASE})")
    parser.add_argument("--scenario", choices=["1","2","3","all"], default="all",
                        help="Which scenario to run (default: all)")
    args = parser.parse_args()

    print(f"\nAdaptive Auth System — Attack Simulator")
    print(f"Target: {args.base_url}")

    # Quick liveness check
    try:
        r = httpx.get(f"{args.base_url}/health", timeout=3)
        _print(PASS, f"Server is up: {r.json()}")
    except Exception:
        _print(FAIL, "Server not reachable — is uvicorn running?")
        sys.exit(1)

    run = args.scenario
    if run in ("1", "all"): scenario_legitimate(args.base_url)
    if run in ("2", "all"): scenario_mfa_fatigue(args.base_url)
    if run in ("3", "all"): scenario_brute_force(args.base_url)

    print(f"\n{DIVIDER}")
    print("  Simulation complete. Check the dashboard at:")
    print(f"  {args.base_url}/dashboard")
    print(DIVIDER)


if __name__ == "__main__":
    main()
