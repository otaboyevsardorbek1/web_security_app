"""
WebGuard Pro - Enterprise Web Security Platform
Version 2.0 | FastAPI + Modern Frontend
"""

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from contextlib import asynccontextmanager
import uvicorn
import logging
import time

from routers import scanner, monitor, pentest, auth, dashboard
from core.config import settings
from core.database import init_db
from core.middleware import SecurityHeadersMiddleware, RateLimitMiddleware

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("webguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    logger.info("🛡️ WebGuard Pro starting up...")
    await init_db()
    logger.info("✅ Database initialized")
    yield
    logger.info("🔴 WebGuard Pro shutting down...")


app = FastAPI(
    title="WebGuard Pro",
    description="Enterprise Web Security Platform - Vulnerability Scanner, Monitor, Pentest & Auth",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# ── Middleware ──────────────────────────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# ── Static files & Templates ────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ── Routers ─────────────────────────────────────────────────────────────────
app.include_router(auth.router,      prefix="/api/auth",      tags=["Authentication"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(scanner.router,   prefix="/api/scanner",   tags=["Vulnerability Scanner"])
app.include_router(monitor.router,   prefix="/api/monitor",   tags=["Security Monitor"])
app.include_router(pentest.router,   prefix="/api/pentest",   tags=["Penetration Testing"])


# ── Frontend routes ──────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "WebGuard Pro",
        "version": "2.0.0",
        "timestamp": time.time()
    }

@app.exception_handler(404)
async def not_found(request: Request, exc: HTTPException):
    return JSONResponse(status_code=404, content={"error": "Endpoint not found", "path": str(request.url)})

@app.exception_handler(500)
async def server_error(request: Request, exc: Exception):
    logger.error(f"Internal error: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
