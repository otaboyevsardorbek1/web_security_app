"""Core configuration settings"""
from pydantic_settings import BaseSettings
from typing import List
import secrets


class Settings(BaseSettings):
    APP_NAME: str = "WebGuard Pro"
    VERSION: str = "2.0.0"
    DEBUG: bool = False

    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./webguard.db"

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 100

    # Scanner settings
    SCANNER_TIMEOUT: int = 30
    MAX_CONCURRENT_SCANS: int = 5

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
