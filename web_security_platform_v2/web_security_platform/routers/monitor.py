"""Security Monitor Router"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from typing import Optional, List
import aiohttp
import asyncio
import time
from datetime import datetime, timezone

from core.database import get_db
from core.security import get_current_user
from models import MonitorTarget, Alert, SeverityLevel

router = APIRouter()


class MonitorTargetCreate(BaseModel):
    url: str
    name: str
    check_interval_minutes: int = 5


@router.post("/targets")
async def add_target(
    data: MonitorTargetCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    target = MonitorTarget(
        user_id=current_user["user_id"],
        url=data.url,
        name=data.name,
        check_interval_minutes=data.check_interval_minutes,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return {"id": target.id, "name": target.name, "url": target.url, "status": "monitoring started"}


@router.get("/targets")
async def list_targets(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(MonitorTarget).where(MonitorTarget.user_id == current_user["user_id"])
    )
    targets = result.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "url": t.url,
            "is_active": t.is_active,
            "last_status": t.last_status,
            "last_response_time_ms": t.last_response_time_ms,
            "uptime_percentage": t.uptime_percentage,
            "last_checked": t.last_checked.isoformat() if t.last_checked else None,
        }
        for t in targets
    ]


@router.post("/check/{target_id}")
async def check_target(
    target_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(MonitorTarget).where(MonitorTarget.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    start = time.time()
    status_code = None
    error = None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target.url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                status_code = resp.status
    except Exception as e:
        error = str(e)

    elapsed_ms = int((time.time() - start) * 1000)
    status_str = "up" if status_code and status_code < 400 else "down"

    target.last_checked = datetime.now(timezone.utc)
    target.last_status = status_str
    target.last_response_time_ms = elapsed_ms
    await db.commit()

    if status_str == "down":
        alert = Alert(
            user_id=current_user["user_id"],
            title=f"Target Down: {target.name}",
            message=f"{target.url} is unreachable. Error: {error or f'HTTP {status_code}'}",
            severity=SeverityLevel.HIGH,
            source="monitor",
            metadata={"target_id": target_id, "error": error}
        )
        db.add(alert)
        await db.commit()

    return {
        "target": target.name,
        "url": target.url,
        "status": status_str,
        "http_code": status_code,
        "response_time_ms": elapsed_ms,
        "error": error,
        "checked_at": datetime.now(timezone.utc).isoformat()
    }


@router.get("/alerts")
async def get_alerts(
    unread_only: bool = False,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Alert).where(Alert.user_id == current_user["user_id"])
    if unread_only:
        query = query.where(Alert.is_read == False)
    query = query.order_by(Alert.created_at.desc()).limit(100)

    result = await db.execute(query)
    alerts = result.scalars().all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "message": a.message,
            "severity": a.severity.value,
            "source": a.source,
            "is_read": a.is_read,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ]


@router.put("/alerts/{alert_id}/read")
async def mark_read(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.is_read = True
    await db.commit()
    return {"message": "Marked as read"}
