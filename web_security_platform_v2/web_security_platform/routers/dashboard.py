"""Dashboard statistics router"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from datetime import datetime, timezone, timedelta

from core.database import get_db
from core.security import get_current_user
from models import Scan, Finding, Alert, MonitorTarget, ScanStatus, SeverityLevel

router = APIRouter()


@router.get("/stats")
async def get_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    uid = current_user["user_id"]

    # Total scans
    total_scans = await db.scalar(select(func.count(Scan.id)).where(Scan.user_id == uid))

    # Active scans
    active_scans = await db.scalar(
        select(func.count(Scan.id)).where(
            and_(Scan.user_id == uid, Scan.status == ScanStatus.RUNNING)
        )
    )

    # Total vulnerabilities
    total_vulns = await db.scalar(
        select(func.sum(Scan.vulnerabilities_found)).where(Scan.user_id == uid)
    ) or 0

    # Critical findings
    critical_count = await db.scalar(
        select(func.count(Finding.id))
        .join(Scan)
        .where(
            and_(Scan.user_id == uid, Finding.severity == SeverityLevel.CRITICAL)
        )
    ) or 0

    # Unread alerts
    unread_alerts = await db.scalar(
        select(func.count(Alert.id)).where(
            and_(Alert.user_id == uid, Alert.is_read == False)
        )
    ) or 0

    # Monitor targets
    total_targets = await db.scalar(
        select(func.count(MonitorTarget.id)).where(MonitorTarget.user_id == uid)
    ) or 0

    targets_up = await db.scalar(
        select(func.count(MonitorTarget.id)).where(
            and_(MonitorTarget.user_id == uid, MonitorTarget.last_status == "up")
        )
    ) or 0

    # Recent scans (last 7 days)
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_scans = await db.scalar(
        select(func.count(Scan.id)).where(
            and_(Scan.user_id == uid, Scan.created_at >= week_ago)
        )
    ) or 0

    # Average risk score
    avg_risk = await db.scalar(
        select(func.avg(Scan.risk_score)).where(
            and_(Scan.user_id == uid, Scan.status == ScanStatus.COMPLETED)
        )
    ) or 0.0

    return {
        "total_scans": total_scans or 0,
        "active_scans": active_scans or 0,
        "total_vulnerabilities": int(total_vulns),
        "critical_findings": critical_count,
        "unread_alerts": unread_alerts,
        "monitor_targets": {"total": total_targets, "up": targets_up, "down": total_targets - targets_up},
        "recent_scans_7d": recent_scans,
        "average_risk_score": round(float(avg_risk), 1),
    }


@router.get("/recent-scans")
async def recent_scans(
    limit: int = 10,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user["user_id"])
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    scans = result.scalars().all()
    return [
        {
            "id": s.id,
            "target_url": s.target_url,
            "scan_type": s.scan_type,
            "status": s.status.value,
            "risk_score": s.risk_score,
            "vulnerabilities_found": s.vulnerabilities_found,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


@router.get("/severity-breakdown")
async def severity_breakdown(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Finding.severity, func.count(Finding.id).label("count"))
        .join(Scan)
        .where(Scan.user_id == current_user["user_id"])
        .group_by(Finding.severity)
    )
    rows = result.all()
    return {row.severity.value: row.count for row in rows}
