# Behaviour-Based Adaptive Authentication System
## MFA Fatigue Detection — Setup & Run Guide

---

### Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.11+ |
| MySQL Server | 8.0+ |
| pip | latest |

---

### 1 — Clone / place the project

```
cloud_project_07/
├── app/
│   ├── main.py
│   ├── api/          (auth, mfa, risk, logs, pages, schemas)
│   ├── core/         (config, security)
│   ├── db/           (base, session)
│   ├── models/       (user, auth_event, risk_decision)
│   ├── services/     (auth_service, behaviour_monitor, risk_engine, decision_controller)
│   └── templates/    (login, register, mfa, dashboard HTML)
├── requirements.txt
├── .env.example
└── SETUP.md
```

---

### 2 — Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

---

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4 — Create the MySQL database

```sql
-- Run in MySQL shell or Workbench
CREATE DATABASE adaptive_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

---

### 5 — Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```
DB_PASSWORD=your_mysql_root_password
SECRET_KEY=<run: python -c "import secrets; print(secrets.token_hex(32))">
```

---

### 6 — Start the server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

On first start, SQLAlchemy calls `create_all()` which creates all
three tables automatically — no migration tool needed.

---

### 7 — Open the application

| URL | Purpose |
|-----|---------|
| http://localhost:8000/ | Login page |
| http://localhost:8000/register | Registration page |
| http://localhost:8000/mfa | MFA approval page |
| http://localhost:8000/dashboard | Risk dashboard |
| http://localhost:8000/docs | Swagger UI (all APIs) |
| http://localhost:8000/redoc | ReDoc documentation |

---

### 8 — Database schema (auto-created)

```sql
-- users
CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64) UNIQUE NOT NULL,
  password_hash VARCHAR(128) NOT NULL,
  created_at    DATETIME NOT NULL
);

-- auth_events
CREATE TABLE auth_events (
  event_id    INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL REFERENCES users(id),
  event_type  ENUM('LOGIN','MFA_REQUEST','APPROVE','DENY') NOT NULL,
  ip_address  VARCHAR(45) NOT NULL,
  device_info VARCHAR(256),
  timestamp   DATETIME NOT NULL,
  INDEX (user_id),
  INDEX (timestamp)
);

-- risk_decisions
CREATE TABLE risk_decisions (
  decision_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL REFERENCES users(id),
  risk_score  INT NOT NULL,
  decision    ENUM('ALLOW','VERIFY','BLOCK') NOT NULL,
  reason      VARCHAR(512) NOT NULL,
  timestamp   DATETIME NOT NULL,
  INDEX (user_id),
  INDEX (timestamp)
);
```

---

### 9 — API Quick Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/register | Register new user |
| POST | /api/login | Login, receive JWT |
| POST | /api/mfa/request?user_id=N | Issue MFA challenge |
| POST | /api/mfa/respond | Approve / deny MFA |
| GET | /api/risk/evaluate?user_id=N | Run risk evaluation |
| GET | /api/logs/events?user_id=N | Auth event log |
| GET | /api/logs/decisions?user_id=N | Risk decision history |
| GET | /health | Liveness probe |

---

### 10 — Risk Scoring Reference

| Signal | Weight | Trigger Condition |
|--------|--------|-------------------|
| excess_mfa_requests | 30 | >3 MFA requests in 2 min |
| rapid_login_attempts | 20 | >5 logins in 5 min |
| repeated_approvals | 25 | >3 approvals in 2 min |

| Score Range | Decision | Action |
|-------------|----------|--------|
| 0 – 39 | ALLOW | Grant access |
| 40 – 69 | VERIFY | Require step-up auth |
| 70+ | BLOCK | Deny access |

---

### 11 — Simulating an MFA Fatigue Attack (Swagger)

1. Register a user via `POST /api/register`.
2. Login via `POST /api/login` — copy `user_id`.
3. Call `POST /api/mfa/request?user_id=<id>` **four times** in quick succession.
4. Call `POST /api/mfa/respond` with `approved: true` twice.
5. Call `GET /api/risk/evaluate?user_id=<id>`.
6. Observe `risk_score >= 55` and `decision = BLOCK`.
