"""Authentication & User Management Router"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime, timezone
import re

from core.database import get_db
from core.security import hash_password, verify_password, create_access_token, create_refresh_token, get_current_user
from models import User, LoginAttempt, UserRole

router = APIRouter()

MAX_FAILED_ATTEMPTS = 5


# ── Schemas ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]{3,50}$", v):
            raise ValueError("Username must be 3-50 alphanumeric characters")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain a digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain a special character")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    user: dict


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/register", status_code=201)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Check existing user
    result = await db.execute(
        select(User).where((User.username == data.username) | (User.email == data.email))
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already registered")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        role=UserRole.USER,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {
        "message": "Registration successful",
        "user_id": user.id,
        "username": user.username
    }


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    result = await db.execute(select(User).where(User.username == data.username))
    user = result.scalar_one_or_none()

    async def log_attempt(success: bool, reason: str = None):
        attempt = LoginAttempt(
            username=data.username,
            ip_address=ip,
            user_agent=user_agent,
            success=success,
            failure_reason=reason
        )
        db.add(attempt)
        await db.commit()

    # Account lock check
    if user and user.locked_until and user.locked_until > datetime.now(timezone.utc):
        await log_attempt(False, "account_locked")
        raise HTTPException(status_code=423, detail="Account temporarily locked due to too many failed attempts")

    if not user or not verify_password(data.password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                from datetime import timedelta
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            await db.commit()
        await log_attempt(False, "invalid_credentials")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.is_active:
        await log_attempt(False, "inactive_account")
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Reset failed attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    token_data = {"sub": user.username, "role": user.role.value, "user_id": user.id}
    await log_attempt(True)

    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=create_refresh_token(token_data),
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value
        }
    )


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    # In production: blacklist the token in Redis
    return {"message": "Logged out successfully"}


@router.get("/login-history")
async def login_history(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(LoginAttempt)
        .where(LoginAttempt.username == current_user["username"])
        .order_by(LoginAttempt.created_at.desc())
        .limit(20)
    )
    attempts = result.scalars().all()
    return [
        {
            "ip": a.ip_address,
            "success": a.success,
            "reason": a.failure_reason,
            "time": a.created_at.isoformat() if a.created_at else None,
            "user_agent": a.user_agent
        }
        for a in attempts
    ]
