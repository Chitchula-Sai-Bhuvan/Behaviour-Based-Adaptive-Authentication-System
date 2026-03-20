# -*- coding: utf-8 -*-
"""
auth_failure_demo.py
---------------------
Step-wise demonstration of every authorization failure mode.
Run: python tests/auth_failure_demo.py
"""

import urllib.request
import urllib.error
import json
import sys

# Force UTF-8 output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE = "http://localhost:8000"


def post(url, data, extra_headers=None):
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def sep(title):
    print("\n" + "=" * 60)
    print("  " + title)
    print("=" * 60)


# ===========================================================
# SETUP: Register a valid user and get tokens
# ===========================================================
sep("SETUP - Register a valid user + login")
s, b = post(f"{BASE}/api/register", {"username": "demo_fail_user", "password": "SecurePass1!"})
print(f"  Register Status : {s}")
print(f"  Response        : {b}")

s, b = post(f"{BASE}/api/login", {"username": "demo_fail_user", "password": "SecurePass1!"})
VALID_ACCESS  = b.get("access_token", "")
VALID_REFRESH = b.get("refresh_token", "")
VALID_SESSION = b.get("session_id", "")
VALID_UID     = b.get("user_id")
print(f"\n  Login Status    : {s}")
print(f"  user_id         : {VALID_UID}")
print(f"  session_id      : {VALID_SESSION}")
print(f"  access_token    : {VALID_ACCESS[:50]}...")
print(f"  refresh_token   : {VALID_REFRESH[:50]}...")


# ===========================================================
# FAILURE 1 - Wrong Password
# ===========================================================
sep("FAILURE 1 - Wrong Password  [Expected HTTP 401]")
s, b = post(f"{BASE}/api/login", {"username": "demo_fail_user", "password": "WrongPass999"})
print(f"  Status   : {s}  (expected 401)")
print(f"  Response : {b}")
print()
print("  ROOT CAUSE:")
print("    verify_password() does bcrypt comparison -> returns False")
print("    authenticate_user() returns (None, 'bad_password')")
print("    login() raises HTTPException 401 'Invalid credentials.'")
print("    failed_login_attempts counter is incremented in the DB")


# ===========================================================
# FAILURE 2 - Non-existent Username
# ===========================================================
sep("FAILURE 2 - Non-existent Username  [Expected HTTP 401]")
s, b = post(f"{BASE}/api/login", {"username": "no_such_user_xyz", "password": "AnyPass1!"})
print(f"  Status   : {s}  (expected 401)")
print(f"  Response : {b}")
print()
print("  ROOT CAUSE:")
print("    get_user_by_username() returns None -> 'not_found'")
print("    SAME 401 response as wrong password (prevents user enumeration)")


# ===========================================================
# FAILURE 3 - Weak Password during Registration
# ===========================================================
sep("FAILURE 3 - Weak Password on Register  [Expected HTTP 422]")
cases = [
    ("u_short",    "abc",        "too short (<8 chars)"),
    ("u_noupper",  "password1!", "no uppercase letter"),
    ("u_nodigit",  "Password!",  "no digit"),
    ("u_nospec",   "Password1",  "no special character"),
]
for uname, pw, label in cases:
    s, b = post(f"{BASE}/api/register", {"username": uname, "password": pw})
    detail = b.get("detail")
    print(f"  [{label}]")
    print(f"    Status: {s} | {detail}")
print()
print("  ROOT CAUSE:")
print("    validate_password_policy() in core/security.py checks:")
print("      - Minimum length >= 8")
print("      - At least one uppercase letter")
print("      - At least one digit [0-9]")
print("      - At least one special character  (!@#...)")
print("    Violations collected -> PasswordPolicyError -> HTTP 422")


# ===========================================================
# FAILURE 4 - Duplicate Username
# ===========================================================
sep("FAILURE 4 - Duplicate Username  [Expected HTTP 409]")
s, b = post(f"{BASE}/api/register", {"username": "demo_fail_user", "password": "SecurePass1!"})
print(f"  Status   : {s}  (expected 409)")
print(f"  Response : {b}")
print()
print("  ROOT CAUSE:")
print("    create_user() queries DB for existing username")
print("    Finds existing row -> raises DuplicateUsernameError -> HTTP 409 Conflict")


# ===========================================================
# FAILURE 5 - Account Lockout (brute-force threshold)
# ===========================================================
sep("FAILURE 5 - Account Lockout after 5 Bad Passwords  [Expected HTTP 401 -> 'locked']")
# Fresh user for clean lockout demo
post(f"{BASE}/api/register", {"username": "lockout_demo_99", "password": "SecurePass1!"})
print("  Registered fresh user: lockout_demo_99")
print()
for i in range(1, 8):
    s, b = post(f"{BASE}/api/login", {"username": "lockout_demo_99", "password": "BadPass!"})
    detail = b.get("detail")
    marker = "  <<< LOCKED" if "locked" in str(detail).lower() else ""
    print(f"  Attempt {i} -> HTTP {s} | {detail}{marker}")
print()
print("  ROOT CAUSE:")
print("    _record_failed_attempt() increments user.failed_login_attempts")
print("    At attempt 5 (MAX_FAILED_LOGINS=5):")
print("      user.locked_until = now + LOCKOUT_DURATION_MINUTES (15 min)")
print("    Attempt 6+ hits is_locked() check BEFORE password verification")
print("    Returns (None, 'locked') -> HTTP 401 'Account is temporarily locked.'")


# ===========================================================
# FAILURE 6 - Invalid / Tampered JWT Signature
# ===========================================================
sep("FAILURE 6 - Invalid / Tampered JWT  [Expected HTTP 401]")
# /api/refresh is the main endpoint that validates JWT signatures
fake_token = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJoYWNrZXIiLCJ0eXBlIjoicmVmcmVzaCIsInVzZXJfaWQiOjl9"
    ".FAKESIGNATUREXXXXXXXXXXXXXXXXXXXXXXXXX"
)
s, b = post(f"{BASE}/api/refresh", {"refresh_token": fake_token})
print(f"  Status   : {s}  (expected 401)")
print(f"  Response : {b}")
print()
print("  ROOT CAUSE:")
print("    decode_token() calls jose.jwt.decode()")
print("    Bad signature -> JWTError raised internally")
print("    Caught by except block -> returns None")
print("    refresh endpoint: 'if not decoded' -> HTTP 401 'Invalid refresh token.'")


# ===========================================================
# FAILURE 7 - Expired JWT
# ===========================================================
sep("FAILURE 7 - Expired JWT  [Expected HTTP 401]")
# Token with exp=1590000000 (year 2020, definitely expired)
# Signed with wrong key intentionally, so it registers as invalid (same outcome)
expired_token = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJ0ZXN0IiwidHlwZSI6InJlZnJlc2giLCJ1c2VyX2lkIjoxLCJleHAiOjE1OTAwMDAwMDB9"
    ".EXPIREDSIG"
)
s, b = post(f"{BASE}/api/refresh", {"refresh_token": expired_token})
print(f"  Status   : {s}  (expected 401)")
print(f"  Response : {b}")
print()
print("  ROOT CAUSE:")
print("    jwt.decode() sees exp < now -> raises ExpiredSignatureError (subclass of JWTError)")
print("    decode_token() catches exception -> returns None")
print("    refresh endpoint raises HTTP 401 'Invalid refresh token.'")


# ===========================================================
# FAILURE 8 - Token Revocation (logout + re-use of refresh token)
# ===========================================================
sep("FAILURE 8 - Re-use of a Rotated/Revoked Refresh Token  [Expected HTTP 401]")
# Get a fresh login
s, login_b = post(f"{BASE}/api/login", {"username": "demo_fail_user", "password": "SecurePass1!"})
fresh_refresh = login_b.get("refresh_token", "")
fresh_session = login_b.get("session_id", "")
fresh_access  = login_b.get("access_token", "")
print(f"  Got fresh refresh_token (jti embedded in JWT)")

# Step 1: Logout (access token revoked via Authorization header)
logout_hdrs = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {fresh_access}",
}
s, b = post(f"{BASE}/api/logout", {"session_id": fresh_session}, extra_headers=logout_hdrs)
print(f"  POST /api/logout  -> HTTP {s} | {b}")

# Step 2: Try to refresh using the old refresh token (whose session is now terminated)
# The refresh token itself has NOT been explicitly revoked (logout only revokes access token)
# BUT we can show forced revocation by doing one valid refresh then trying to reuse old token
s2, rotated_b = post(f"{BASE}/api/refresh", {"refresh_token": fresh_refresh})
new_refresh = rotated_b.get("refresh_token", "")
print(f"  1st /api/refresh  -> HTTP {s2} | old refresh JTI now ROTATED (in revoked_tokens)")

# Step 3: Re-use the original (now rotated/revoked) refresh token
s3, b3 = post(f"{BASE}/api/refresh", {"refresh_token": fresh_refresh})
print(f"  Re-use original   -> HTTP {s3}  (expected 401)")
print(f"  Response          : {b3}")
print()
print("  ROOT CAUSE:")
print("    /api/refresh calls revoke_token(old_jti, reason='ROTATED') after first use")
print("    RevokedToken row inserted with old JTI")
print("    Second call: is_token_revoked() finds JTI -> HTTP 401 'Refresh token has been revoked'")


# ===========================================================
# FAILURE 9 - Access Token Used as Refresh Token
# ===========================================================
sep("FAILURE 9 - Access Token Presented as Refresh Token  [Expected HTTP 401]")
s, b = post(f"{BASE}/api/refresh", {"refresh_token": VALID_ACCESS})
print(f"  Status   : {s}  (expected 401)")
print(f"  Response : {b}")
print()
print("  ROOT CAUSE:")
print("    decode_token() successfully decodes the access token (valid signature)")
print("    But decoded['type'] == 'access', not 'refresh'")
print("    Explicit type check in /api/refresh: 'if decoded.get(type) != refresh'")
print("    -> HTTP 401 'Invalid refresh token.'")


# ===========================================================
# FAILURE 10 - Missing Required Body Fields (Pydantic validation)
# ===========================================================
sep("FAILURE 10 - Missing Required Body Fields  [Expected HTTP 422]")
s, b = post(f"{BASE}/api/login", {"username": "demo_fail_user"})   # missing 'password'
print(f"  Status   : {s}  (expected 422)")
detail = b.get("detail")
if isinstance(detail, list):
    for err in detail:
        print(f"  Error    : field='{err.get('loc')}' msg='{err.get('msg')}'")
else:
    print(f"  Detail   : {detail}")
print()
print("  ROOT CAUSE:")
print("    LoginRequest(BaseModel) declares 'password: str' as required")
print("    Pydantic validation runs before the route handler is called")
print("    Missing field -> RequestValidationError -> HTTP 422 Unprocessable Entity")


# ===========================================================
# FAILURE 11 - Too Many Active MFA Challenges (MFA fatigue protection)
# ===========================================================
sep("FAILURE 11 - MFA Challenge Limit Exceeded  [Expected HTTP 429]")
post(f"{BASE}/api/register", {"username": "mfa_flood_user", "password": "SecurePass1!"})
_, mfa_login = post(f"{BASE}/api/login", {"username": "mfa_flood_user", "password": "SecurePass1!"})
mfa_uid = mfa_login.get("user_id")
mfa_sess = mfa_login.get("session_id", "")
print(f"  Registered mfa_flood_user, user_id={mfa_uid}")
print()

for i in range(1, 6):
    s, b = post(f"{BASE}/api/mfa/request?user_id={mfa_uid}&session_id={mfa_sess}", {})
    detail = b.get("detail") or b.get("message", "")
    marker = "  <<< BLOCKED" if s == 429 else ""
    print(f"  MFA request {i} -> HTTP {s} | {detail}{marker}")
print()
print("  ROOT CAUSE:")
print("    issue_challenge() counts active (non-expired, non-responded) challenges")
print("    When count >= MFA_MAX_ACTIVE_CHALLENGES (3):")
print("      raises ValueError('Too many active challenges')")
print("    MFA endpoint catches it -> HTTP 429 Too Many Requests")
print("    SECURITY PURPOSE: Prevents MFA fatigue attacks (spamming approve buttons)")


# ===========================================================
# FAILURE 12 - Invalid MFA Challenge ID
# ===========================================================
sep("FAILURE 12 - Invalid MFA Challenge ID  [Expected HTTP 400]")
s, b = post(f"{BASE}/api/mfa/respond", {
    "user_id": VALID_UID,
    "challenge_id": "00000000-0000-0000-0000-000000000000",
    "approved": True,
})
print(f"  Status   : {s}  (expected 400 or 404)")
print(f"  Response : {b}")
print()
print("  ROOT CAUSE:")
print("    respond_to_challenge() queries: WHERE challenge_id=? AND user_id=?")
print("    No row found -> raises ValueError / HTTPException")
print("    -> HTTP 400 'Challenge not found.' (prevents replay attacks)")


# ===========================================================
print("\n" + "=" * 60)
print("  ALL 12 FAILURE SCENARIOS COMPLETED")
print("=" * 60 + "\n")
