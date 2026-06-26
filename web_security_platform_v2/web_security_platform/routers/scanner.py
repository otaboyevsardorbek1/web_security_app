"""Vulnerability Scanner Router - OWASP Top 10 checks"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
import asyncio
import aiohttp
import re
import time
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.database import get_db
from core.security import get_current_user
from models import Scan, Finding, ScanStatus, SeverityLevel

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str
    scan_types: List[str] = ["headers", "ssl", "injection", "xss", "csrf", "info_disclosure"]


class ScanResponse(BaseModel):
    scan_id: str
    target_url: str
    status: str
    message: str


# ── Scanner Engine ────────────────────────────────────────────────────────────
class VulnerabilityScanner:

    SECURITY_HEADERS = {
        "Strict-Transport-Security": (SeverityLevel.HIGH, "HSTS not set - vulnerable to downgrade attacks"),
        "X-Content-Type-Options": (SeverityLevel.MEDIUM, "Missing nosniff - MIME type sniffing possible"),
        "X-Frame-Options": (SeverityLevel.MEDIUM, "Missing - clickjacking possible"),
        "Content-Security-Policy": (SeverityLevel.HIGH, "No CSP - XSS risk increased"),
        "X-XSS-Protection": (SeverityLevel.LOW, "Browser XSS protection not enabled"),
        "Referrer-Policy": (SeverityLevel.LOW, "No referrer policy - information leakage"),
        "Permissions-Policy": (SeverityLevel.LOW, "No permissions policy set"),
    }

    SQL_PAYLOADS = ["'", "1' OR '1'='1", "'; DROP TABLE users; --", "1 UNION SELECT NULL--"]
    XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "javascript:alert(1)"]

    async def check_security_headers(self, url: str, session: aiohttp.ClientSession) -> List[dict]:
        findings = []
        try:
            async with session.get(url, allow_redirects=True) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                server = resp.headers.get("Server", "")
                x_powered = resp.headers.get("X-Powered-By", "")

                for header, (severity, message) in self.SECURITY_HEADERS.items():
                    if header.lower() not in headers:
                        findings.append({
                            "title": f"Missing Security Header: {header}",
                            "description": message,
                            "severity": severity.value,
                            "category": "Security Headers",
                            "affected_url": url,
                            "remediation": f"Add '{header}' header to all HTTP responses",
                            "evidence": f"Header '{header}' not found in response"
                        })

                if server:
                    findings.append({
                        "title": "Server Version Disclosure",
                        "description": f"Server header reveals: {server}",
                        "severity": SeverityLevel.LOW.value,
                        "category": "Information Disclosure",
                        "affected_url": url,
                        "remediation": "Remove or obfuscate the Server header",
                        "evidence": f"Server: {server}"
                    })

                if x_powered:
                    findings.append({
                        "title": "Technology Disclosure (X-Powered-By)",
                        "description": f"X-Powered-By reveals: {x_powered}",
                        "severity": SeverityLevel.LOW.value,
                        "category": "Information Disclosure",
                        "affected_url": url,
                        "remediation": "Remove X-Powered-By header",
                        "evidence": f"X-Powered-By: {x_powered}"
                    })
        except Exception as e:
            findings.append({
                "title": "Connection Error",
                "description": f"Could not connect: {str(e)}",
                "severity": SeverityLevel.INFO.value,
                "category": "Connectivity",
                "affected_url": url,
                "remediation": "Verify the target URL is reachable",
                "evidence": str(e)
            })
        return findings

    async def check_ssl(self, url: str) -> List[dict]:
        findings = []
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            findings.append({
                "title": "No HTTPS",
                "description": "Target uses HTTP instead of HTTPS",
                "severity": SeverityLevel.HIGH.value,
                "category": "SSL/TLS",
                "affected_url": url,
                "remediation": "Enable HTTPS with a valid SSL/TLS certificate",
                "evidence": "URL scheme is http://"
            })
            return findings

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()

                    # Check protocol version
                    if proto in ["TLSv1", "TLSv1.1", "SSLv3"]:
                        findings.append({
                            "title": f"Outdated TLS Version: {proto}",
                            "description": f"Using deprecated protocol {proto}",
                            "severity": SeverityLevel.HIGH.value,
                            "category": "SSL/TLS",
                            "affected_url": url,
                            "remediation": "Upgrade to TLS 1.2 or TLS 1.3",
                            "evidence": f"Negotiated protocol: {proto}"
                        })

                    # Check cert expiry
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        import ssl as ssl_mod
                        exp_time = ssl_mod.cert_time_to_seconds(not_after)
                        remaining = exp_time - time.time()
                        days_left = remaining / 86400
                        if days_left < 30:
                            findings.append({
                                "title": "SSL Certificate Expiring Soon",
                                "description": f"Certificate expires in {int(days_left)} days",
                                "severity": SeverityLevel.HIGH.value,
                                "category": "SSL/TLS",
                                "affected_url": url,
                                "remediation": "Renew the SSL certificate immediately",
                                "evidence": f"Expires: {not_after}"
                            })

        except ssl.SSLError as e:
            findings.append({
                "title": "SSL Certificate Error",
                "description": str(e),
                "severity": SeverityLevel.CRITICAL.value,
                "category": "SSL/TLS",
                "affected_url": url,
                "remediation": "Fix SSL certificate configuration",
                "evidence": str(e)
            })
        except Exception:
            pass

        return findings

    async def check_common_paths(self, url: str, session: aiohttp.ClientSession) -> List[dict]:
        """Check for exposed sensitive files/directories"""
        findings = []
        sensitive_paths = [
            ("/.git/config", "Git repository exposed"),
            ("/.env", "Environment file exposed"),
            ("/config.php", "PHP config exposed"),
            ("/phpinfo.php", "PHP info exposed"),
            ("/admin", "Admin panel accessible"),
            ("/wp-admin", "WordPress admin exposed"),
            ("/robots.txt", "Robots.txt (check for sensitive paths)"),
            ("/.htaccess", "Apache config exposed"),
            ("/backup.zip", "Backup file exposed"),
            ("/api/v1/users", "User enumeration possible"),
        ]

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for path, desc in sensitive_paths:
            try:
                async with session.get(f"{base}{path}", allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status in [200, 301, 302, 403]:
                        findings.append({
                            "title": f"Sensitive Path Accessible: {path}",
                            "description": desc,
                            "severity": SeverityLevel.MEDIUM.value if r.status == 403 else SeverityLevel.HIGH.value,
                            "category": "Information Disclosure",
                            "affected_url": f"{base}{path}",
                            "remediation": f"Restrict access to {path} or remove it",
                            "evidence": f"HTTP {r.status} response"
                        })
            except Exception:
                pass

        return findings

    async def run_full_scan(self, scan_id: str, url: str, scan_types: list, db: AsyncSession):
        """Run all checks asynchronously"""
        # Update status to running
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        all_findings = []
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(ssl=False)

        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                tasks = []
                if "headers" in scan_types:
                    tasks.append(self.check_security_headers(url, session))
                if "ssl" in scan_types:
                    tasks.append(self.check_ssl(url))
                if "info_disclosure" in scan_types:
                    tasks.append(self.check_common_paths(url, session))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, list):
                        all_findings.extend(r)

            # Persist findings
            for f in all_findings:
                finding = Finding(
                    scan_id=scan_id,
                    title=f["title"],
                    description=f["description"],
                    severity=SeverityLevel(f["severity"]),
                    category=f["category"],
                    affected_url=f.get("affected_url", url),
                    evidence=f.get("evidence"),
                    remediation=f.get("remediation"),
                )
                db.add(finding)

            # Calculate risk score
            severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
            total_score = sum(severity_weights.get(f["severity"], 0) for f in all_findings)
            risk_score = min(100.0, total_score * 2.0)

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.vulnerabilities_found = len(all_findings)
            scan.risk_score = risk_score
            scan.results = {"total_findings": len(all_findings), "risk_score": risk_score}
            await db.commit()

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()


scanner_engine = VulnerabilityScanner()


# ── API Endpoints ─────────────────────────────────────────────────────────────
@router.post("/start", response_model=ScanResponse)
async def start_scan(
    data: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    scan = Scan(
        user_id=current_user["user_id"],
        target_url=data.target_url,
        scan_type="vulnerability",
        status=ScanStatus.PENDING
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(
        scanner_engine.run_full_scan,
        scan.id, data.target_url, data.scan_types, db
    )

    return ScanResponse(
        scan_id=scan.id,
        target_url=data.target_url,
        status="pending",
        message="Scan started successfully"
    )


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get findings
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status.value,
        "risk_score": scan.risk_score,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category,
                "affected_url": f.affected_url,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in findings
        ]
    }


@router.get("/")
async def list_scans(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Scan)
        .where(Scan.user_id == current_user["user_id"])
        .order_by(Scan.created_at.desc())
        .limit(50)
    )
    scans = result.scalars().all()
    return [
        {
            "id": s.id,
            "target_url": s.target_url,
            "status": s.status.value,
            "risk_score": s.risk_score,
            "vulnerabilities_found": s.vulnerabilities_found,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]
