# AGENTS

This repository contains three separate Python web security analyzer applications. Use the version-specific directory that matches the user's request.

## Versions

### `Web_Security_Analyzer_v1`
- Legacy Flask monolith.
- Main logic is in `Web_Security_Analyzer_v1/main.py`.
- Uses Flask, Flask-Limiter, Flask-WTF CSRF, Flask-SocketIO, BeautifulSoup, ReportLab, and SQLite.
- Good for reference, regression, or compatibility tasks.

### `Web_Security_Analyzer_v3`
- Latest Flask-based security analyzer.
- Main code is in `Web_Security_Analyzer_v3/main_v3.py`.
- Strong security focus: JWT auth, API keys, CSRF, rate limiting, SSRF/path traversal protections, audit logging, PDF reports, email notifications, compliance checks.
- Uses `.env`-style configuration and explicit requirements in `Web_Security_Analyzer_v3/requirements_v3.txt`.
- Primary target for new feature work and security improvements.

### `web_security_platform_v2/web_security_platform`
- FastAPI-based platform with modular backend architecture.
- Entry point is `web_security_platform_v2/web_security_platform/main.py`.
- Contains routers in `routers/`, core services in `core/`, and templates/static assets for frontend.
- Uses `requirements.txt`, async SQLAlchemy, JWT auth, rate limiting, and structured Pydantic settings.
- Treat this as a separate FastAPI project when making changes.

## Setup and Run

### v3
```bash
cd Web_Security_Analyzer_v3
python -m venv venv
source venv/bin/activate
pip install -r requirements_v3.txt
python main_v3.py
```

### v2 / `web_security_platform_v2`
```bash
cd web_security_platform_v2/web_security_platform
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python setup.py
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### v1
- No dedicated `requirements.txt` found in `Web_Security_Analyzer_v1`.
- The app imports Flask, Flask-Limiter, Flask-WTF CSRF, Flask-SocketIO, requests, BeautifulSoup, ReportLab, whois, and SQLite.

## Key files and directories

- `Web_Security_Analyzer_v3/main_v3.py`
- `Web_Security_Analyzer_v3/requirements_v3.txt`
- `Web_Security_Analyzer_v3/README_v3.md`
- `Web_Security_Analyzer_v3/LOYIHA_XULOSA.md`
- `Web_Security_Analyzer_v3/COMPARISON.md`
- `Web_Security_Analyzer_v1/main.py`
- `web_security_platform_v2/web_security_platform/main.py`
- `web_security_platform_v2/web_security_platform/requirements.txt`
- `web_security_platform_v2/web_security_platform/README.md`
- `web_security_platform_v2/web_security_platform/core/`
- `web_security_platform_v2/web_security_platform/routers/`

## Notes for AI agents

- Do not assume the same framework across versions.
- Prefer `Web_Security_Analyzer_v3` for new development and security work.
- Use `web_security_platform_v2` when the user specifically asks about FastAPI, async routers, or the modern backend architecture.
- Use `Web_Security_Analyzer_v1` only for legacy support or when asked about the original Flask monolith.
- When answering questions about setup or runtime, link to the version-specific README files.
