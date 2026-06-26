# 🛡️ WebGuard Pro — Enterprise Web Security Platform

**Version 2.0** | FastAPI + Modern Dark UI | Full-Stack Python

---

## 🚀 Features

### 1. 🔍 Vulnerability Scanner
- Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS certificate validation and protocol checks
- Information disclosure detection (Git repos, .env files, phpinfo, etc.)
- Background async scanning with real-time status polling
- Risk scoring (0–100) with severity breakdown

### 2. 📡 Security Monitor
- HTTP/HTTPS uptime monitoring
- Response time tracking
- Automatic down alerts
- Configurable check intervals

### 3. 🐛 Penetration Testing
- Async port scanner (21 common ports)
- Cookie security analysis (Secure, HttpOnly, SameSite)
- Directory brute-force (common sensitive paths)
- Header analysis
- Risk-scored findings

### 4. 🔐 Authentication & Security
- JWT access + refresh tokens
- Bcrypt password hashing
- Account lockout after 5 failed attempts (15-min lockout)
- Password strength validation (uppercase, number, symbol)
- Login history tracking (IP, user-agent, success/fail)
- Rate limiting middleware (100 req/min per IP)
- Full security headers on every response

---

## 🏗️ Architecture

```
web_security_platform/
├── main.py              # FastAPI app, middleware, routes
├── setup.py             # DB init + demo user creation
├── requirements.txt
├── .env.example
├── core/
│   ├── config.py        # Pydantic settings
│   ├── database.py      # Async SQLAlchemy + session
│   ├── security.py      # JWT, bcrypt, auth dependencies
│   └── middleware.py    # Security headers + rate limiter
├── models/
│   └── __init__.py      # User, Scan, Finding, Alert, MonitorTarget, LoginAttempt
├── routers/
│   ├── auth.py          # Register, login, logout, history
│   ├── scanner.py       # Vulnerability scanner engine
│   ├── monitor.py       # Uptime monitor + alerts
│   ├── pentest.py       # Penetration testing engine
│   └── dashboard.py     # Stats, charts, recent activity
├── static/
│   ├── css/style.css    # Dark enterprise theme
│   └── js/app.js        # SPA logic, API calls, UI
└── templates/
    └── index.html       # Single-page app shell
```

---

## ⚡ Quick Start

```bash
# 1. Clone and enter directory
cd web_security_platform

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy env file
cp .env.example .env

# 5. Initialize database + create admin user
python setup.py

# 6. Start the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000**

Login: `admin` / `Admin@1234`

---

## 🔒 Security Features

| Feature | Implementation |
|---|---|
| Password hashing | bcrypt (passlib) |
| Authentication | JWT (RS256 compatible) |
| Account lockout | 5 attempts → 15 min lock |
| Rate limiting | 100 req/min per IP |
| CORS | Configurable origins |
| Security headers | HSTS, CSP, X-Frame, nosniff, etc. |
| SQL injection | SQLAlchemy ORM (parameterized) |
| XSS | Jinja2 auto-escaping |
| Input validation | Pydantic v2 |

---

## 📡 API Endpoints

### Auth
- `POST /api/auth/register` — New account
- `POST /api/auth/login` — Get JWT tokens
- `GET /api/auth/me` — Current user
- `POST /api/auth/logout` — Logout
- `GET /api/auth/login-history` — Auth audit log

### Scanner
- `POST /api/scanner/start` — Start vulnerability scan
- `GET /api/scanner/{id}` — Get scan + findings
- `GET /api/scanner/` — List all scans

### Monitor
- `POST /api/monitor/targets` — Add target
- `GET /api/monitor/targets` — List targets
- `POST /api/monitor/check/{id}` — Manual check
- `GET /api/monitor/alerts` — Security alerts
- `PUT /api/monitor/alerts/{id}/read` — Mark read

### Pentest
- `POST /api/pentest/start` — Launch pentest
- `GET /api/pentest/{id}` — Get results

### Dashboard
- `GET /api/dashboard/stats` — Summary stats
- `GET /api/dashboard/recent-scans` — Recent 10 scans
- `GET /api/dashboard/severity-breakdown` — Chart data

---

## 🔧 Configuration (.env)

```env
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=sqlite+aiosqlite:///./webguard.db
DEBUG=false
RATE_LIMIT_PER_MINUTE=100
SCANNER_TIMEOUT=30
```

---

## ⚠️ Legal Notice

This tool is for authorized security testing only. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 🗺️ Roadmap

- [ ] 2FA (TOTP) support
- [ ] PDF report export
- [ ] Webhook notifications (Slack, Telegram)
- [ ] Scheduled scans (cron-based)
- [ ] PostgreSQL + Redis production setup
- [ ] Docker Compose deployment
- [ ] CVE database integration
