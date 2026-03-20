# Security Policy & Best Practices

## Security Features

This system implements **defence-in-depth** across multiple layers:

### Layer 1: User Authentication
- ✅ **Bcrypt password hashing** (work factor ~100ms)
- ✅ **Account lockout** after 5 failed attempts (15-minute duration)
- ✅ **Password policy enforcement** (min 8 chars, uppercase, digit, special char)
- ✅ **Secure password reset** (email verification, one-time tokens)

### Layer 2: Session Management
- ✅ **Stateful sessions** with expiry (24 hours)
- ✅ **Session invalidation on logout**
- ✅ **Session touch** (refresh `last_active_at` on each request)
- ✅ **Concurrent session limits** (optional config)

### Layer 3: JWT Tokens
- ✅ **Access tokens** (30-minute expiry, HMAC-SHA256 signed)
- ✅ **Refresh tokens** (7-day expiry, separate secret)
- ✅ **Token rotation** (old token revoked on refresh)
- ✅ **JTI (JWT ID) blacklist** for revocation tracking

### Layer 4: Device & Behavioural Tracking
- ✅ **Device fingerprinting** (IP + User-Agent + Language)
- ✅ **Trusted device registry** (registers known devices)
- ✅ **New device detection signal** (triggers risk evaluation)
- ✅ **IP geolocation** (detects impossible travel)

### Layer 5: MFA Fatigue Attack Detection
- ✅ **Excess MFA requests detection** (≥3 in 2 minutes)
- ✅ **Rapid approval detection** (≥3 approvals in 2 minutes)
- ✅ **Challenge replay prevention** (one-time use, TTL)
- ✅ **MFA challenge limit** (max 3 active per user)

### Layer 6: Rate Limiting
- ✅ **Per-IP rate limits** using SlowAPI
- ✅ **Endpoint-specific limits** (login: 10/min, register: 5/min, MFA: 20/min)
- ✅ **Distributed via X-Forwarded-For** (for proxy scenarios)

### Layer 7: Audit Logging
- ✅ **Append-only audit log** (auth_events table)
- ✅ **Tamper-evident hash chain** (SHA-256 linked chain)
- ✅ **All actions logged** (login, logout, MFA, risk decisions)
- ✅ **Structured JSON logs** for SIEM integration

### Layer 8: HTTP Security Headers
- ✅ `Strict-Transport-Security` (HSTS) - forces HTTPS
- ✅ `X-Frame-Options: DENY` - prevents clickjacking
- ✅ `X-Content-Type-Options: nosniff` - prevents MIME sniffing
- ✅ `Content-Security-Policy` - XSS mitigation
- ✅ `Referrer-Policy: strict-origin-when-cross-origin`

## Threat Model

### Attacks This System Protects Against

| Attack | Detection | Response |
|--------|-----------|----------|
| **Brute force password guessing** | Account lockout (5 failures) | Deny login for 15 min |
| **MFA fatigue / approval attack** | Excess_mfa_requests, repeated_approvals signals | Risk score +55, decision = VERIFY or BLOCK |
| **Credential stuffing** | Rapid_login_attempts signal | Risk score +20, decision = ALLOW (but monitored) |
| **Device theft** | New_device_detected signal | Risk score +20, decision = ALLOW (but flagged) |
| **Account takeover from new IP** | IP_change_detected signal | Risk score +15, decision = ALLOW (but monitored) |
| **Impossible travel** | impossible_travel signal | Risk score +40, decision = BLOCK |
| **Token hijacking** | JTI blacklist on logout/revocation | Revoked tokens rejected |
| **Session fixation** | Session IDs are cryptographic UUIDs | Attacker cannot predict |
| **JWT signature forgery** | HS256 verification with secret key | Invalid signature rejected |
| **XSS attacks** | CSP header + Jinja2 auto-escaping | Injected scripts blocked |
| **CSRF attacks** | SameSite=Strict cookies (recommended nginx config) | Cross-origin requests blocked |
| **Man-in-the-Middle** | HSTS header forces HTTPS | Unencrypted connections rejected |

### Attacks This System Does NOT Protect Against

- ❌ **Phishing** — User tricks manually entering credentials on phishing site
- ❌ **Keylogger malware** — Malware captures credentials on user's device
- ❌ **SIM hijacking** — Attacker intercepts OTP via SIM swap (use TOTP instead)
- ❌ **Social engineering** — User voluntarily gives access to attacker
- ❌ **Physical theft** — Attacker physically steals the device

**Mitigation**: Combine this system with user security training, hardware security keys, and endpoint protection.

## Reporting Security Vulnerabilities

🔒 **DO NOT** create public GitHub issues for security vulnerabilities.

### Responsible Disclosure

1. **Email**: security@example.com with:
   - Vulnerability description
   - Steps to reproduce (if applicable)
   - Impact assessment
   - Proposed fix (optional)

2. **Timeline**:
   - We acknowledge within 48 hours
   - We aim to patch within 7 days
   - We credit you publicly (if desired)

3. **Scope**:
   - This repository and all production deployments

---

## Configuration for Production

### Environment Variables (.env)

```env
# Database — use connection pooling
DATABASE_URL=mysql+pymysql://user:pass@db-pool.prod:3306/auth_db
MAX_OVERFLOW=10
POOL_SIZE=20

# Redis — optional but recommended for scale
REDIS_HOST=redis-cluster.prod
REDIS_PORT=6379
REDIS_PASSWORD=strong-random-password

# JWT Secrets — MUST be cryptographically random
SECRET_KEY=your-256-bit-random-key-should-be-generated-with-secrets.token_urlsafe(32)
REFRESH_SECRET_KEY=different-256-bit-random-key

# Security Settings
DEBUG=False
ALLOWED_ORIGINS=https://example.com,https://app.example.com

# Rate Limits — adjust for your traffic
LOGIN_RATE_LIMIT=10/minute
REGISTER_RATE_LIMIT=5/minute
MFA_RATE_LIMIT=20/minute

# Account Lockout
MAX_FAILED_LOGINS=5
LOCKOUT_DURATION_MINUTES=15

# Session
SESSION_EXPIRY_MINUTES=1440  # 24 hours

# MFA
MFA_CHALLENGE_TTL_MINUTES=5
MFA_MAX_ACTIVE_CHALLENGES=3

# Tokens
ACCESS_TOKEN_EXPIRY_MINUTES=30
REFRESH_TOKEN_EXPIRY_DAYS=7
```

### Database Security

```sql
-- 1. Use strong MySQL passwords
ALTER USER 'auth_user'@'localhost' IDENTIFIED BY 'strong-random-password-32-chars';

-- 2. Create read-only user for monitoring
CREATE USER 'auth_read'@'%' IDENTIFIED BY 'monitor-password';
GRANT SELECT ON auth_db.* TO 'auth_read'@'%';

-- 3. Restrict network access
-- Use firewall rules to allow only app servers to connect

-- 4. Enable MySQL audit logging
SET GLOBAL general_log = 'ON';

-- 5. Enable slow query logging for investigation
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;
```

### Redis Security

```bash
# 1. Set strong password
redis-cli CONFIG SET requirepass strong-random-password-32-chars

# 2. Disable dangerous commands
redis-cli CONFIG SET rename-command FLUSHDB ""
redis-cli CONFIG SET rename-command FLUSHALL ""

# 3. Configure persistence
redis-cli CONFIG SET appendonly yes
redis-cli CONFIG SET appendfsync everysec

# 4. Use Redis Sentinel or Cluster for HA
# See: https://redis.io/topics/sentinel
```

### HTTPS & TLS

```nginx
# nginx configuration for HTTPS
server {
    listen 443 ssl http2;
    server_name api.example.com;
    
    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    
    # TLS 1.2+
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    
    # Proxy to FastAPI
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Secrets Management

```bash
# ✅ Use environment variables or secrets managers
# ✅ Rotate secrets regularly (every 90 days)
# ✅ Use different secrets for dev/staging/prod
# ✅ Enable audit logs for secret access

# AWS Secrets Manager example
aws secretsmanager get-secret-value --secret-id auth-system/prod

# HashiCorp Vault example
vault kv get secret/auth-system/prod
```

### Monitoring & Alerting

Set up alerts for:
- ⚠️ Failed login attempts spike (>100/min)
- ⚠️ MFA fatigue attacks detected (multiple BLOCK decisions)
- ⚠️ Impossible travel events (>3/hour)
- ⚠️ New devices from high-risk countries
- ⚠️ Database or Redis connection failures
- ⚠️ Audit log chain verification failures

---

## Security Testing Checklist

- [ ] Run `test_edge_cases.py` for edge case coverage
- [ ] Run `simulate_attacks.py` to verify MFA fatigue detection
- [ ] Penetration test password reset flow
- [ ] Verify JWT tokens cannot be forged
- [ ] Test rate limiting with concurrent requests
- [ ] Verify session invalidation on logout
- [ ] Test tamper-evident hash chain verification
- [ ] Verify database connection is encrypted
- [ ] Check logs for sensitive data leaks
- [ ] Review all error messages for information disclosure

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [JWT Best Practices (RFC 8725)](https://tools.ietf.org/html/rfc8725)
- [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

**Last Updated**: March 20, 2026  
**Version**: 2.0  
**Maintained By**: Chitchula Sai Bhuvan
