#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Security Analyzer - Professional Pentest Platform v3.0
=============================================================
Enhanced version with enterprise-grade security, scalability,
and comprehensive vulnerability scanning capabilities.

Author: Enhanced by AI
Version: 3.0
License: MIT
"""

import sys
import os
import warnings
import logging
import secrets
import hashlib
import hmac
import time
import datetime
import re
import json
import threading
import concurrent.futures
import ipaddress
import socket
import ssl
import smtplib
import sqlite3
from functools import wraps
from urllib.parse import urlparse, urljoin
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# Suppress cryptography warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="OpenSSL")

# Third-party imports
try:
    from flask import (
        Flask, render_template, request, jsonify, session, 
        send_file, send_from_directory, abort, g
    )
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    from flask_socketio import SocketIO, emit, join_room, leave_room
    from flask_talisman import Talisman
    from flask_cors import CORS
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.utils import secure_filename
    from werkzeug.middleware.proxy_fix import ProxyFix
    import requests
    from bs4 import BeautifulSoup
    import dns.resolver
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, 
        Paragraph, Spacer, PageBreak
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    import jwt
    from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
except ImportError as e:
    print(f"❌ Required dependency missing: {e}")
    print("Please install all dependencies: pip install -r requirements.txt")
    sys.exit(1)

# Optional imports with fallbacks
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import OpenSSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except (ImportError, TypeError, AttributeError):
    WHOIS_AVAILABLE = False
    class WhoisFallback:
        def whois(self, domain):
            return {
                'registrar': 'N/A',
                'creation_date': 'N/A',
                'expiration_date': 'N/A',
                'name_servers': [],
                'status': 'N/A'
            }
    whois = WhoisFallback()

# =========================
# CONFIGURATION
# =========================
class Config:
    """Application configuration with environment variable support."""

    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_urlsafe(32)
    JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', '3600'))
    JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', '604800'))

    # CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Session
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(hours=1)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # File Upload
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'json', 'xml'}

    # Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'users.db')

    # Rate Limiting
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = "100 per hour"

    # Email
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    SMTP_FROM = os.environ.get('SMTP_FROM', 'noreply@websecurity.app')

    # Scanning
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '30'))
    MAX_THREADS = int(os.environ.get('MAX_THREADS', '10'))

    # Security Headers
    SECURITY_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com fonts.googleapis.com; font-src 'self' fonts.gstatic.com; img-src 'self' data:; connect-src 'self' ws: wss:;",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'X-Permitted-Cross-Domain-Policies': 'none',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    }

    # Blocked IPs/Ranges
    BLOCKED_IPS = set()
    BLOCKED_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
    ]

# =========================
# APP INITIALIZATION
# =========================
app = Flask(__name__)
app.config.from_object(Config)

# Proxy fix for reverse proxy deployments
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Security headers via Talisman
Talisman(
    app,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy=Config.SECURITY_HEADERS['Content-Security-Policy'],
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy=Config.SECURITY_HEADERS['Permissions-Policy']
)

# CORS configuration
CORS(app, resources={
    r"/api/*": {
        "origins": os.environ.get('CORS_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization", "X-CSRF-Token"]
    }
})

# SocketIO with proper configuration
socketio = SocketIO(
    app, 
    cors_allowed_origins=os.environ.get('SOCKETIO_CORS', '*'),
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    max_http_buffer_size=1024 * 1024
)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATELIMIT_DEFAULT],
    storage_uri=Config.RATELIMIT_STORAGE_URI,
    strategy=Config.RATELIMIT_STRATEGY
)

# CSRF Protection
csrf = CSRFProtect(app)

# Reports directory
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('pentest.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Audit logger
audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler('audit.log', encoding='utf-8')
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s - AUDIT - %(message)s'
))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

# =========================
# UTILITY FUNCTIONS
# =========================
def sanitize_input(value, max_length=255, allow_html=False):
    """Sanitize user input to prevent injection attacks."""
    if not isinstance(value, str):
        return str(value)[:max_length]

    # Remove null bytes
    value = value.replace('\x00', '').replace('\0', '')

    # Strip whitespace
    value = value.strip()

    # Length check
    value = value[:max_length]

    if not allow_html:
        # Remove HTML tags
        value = re.sub(r'<[^>]+>', '', value)

    return value

def validate_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_url(url):
    """Validate and sanitize URL."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme in ('http', 'https'):
            return None
        if not parsed.netloc:
            return None
        return url
    except Exception:
        return None

def is_private_ip(ip_str):
    """Check if IP is in private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in Config.BLOCKED_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        return False

def is_blocked_url(url):
    """Check if URL points to blocked/internal resources."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return True

        # Check localhost
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
            return True

        # Check IP addresses
        try:
            ip = socket.getaddrinfo(hostname, None)[0][4][0]
            if is_private_ip(ip):
                return True
        except socket.gaierror:
            pass

        # Check blocked IPs
        if hostname in Config.BLOCKED_IPS:
            return True

        return False
    except Exception:
        return True

def generate_secure_token(length=32):
    """Generate cryptographically secure token."""
    return secrets.token_urlsafe(length)

def generate_jwt_token(user_id, username, role, token_type='access'):
    """Generate JWT token."""
    now = datetime.datetime.utcnow()
    if token_type == 'access':
        exp = now + datetime.timedelta(seconds=Config.JWT_ACCESS_TOKEN_EXPIRES)
    else:
        exp = now + datetime.timedelta(seconds=Config.JWT_REFRESH_TOKEN_EXPIRES)

    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'type': token_type,
        'iat': now,
        'exp': exp,
        'jti': generate_secure_token(16)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')

def verify_jwt_token(token, token_type='access'):
    """Verify JWT token."""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        if payload.get('type') != token_type:
            return None
        return payload
    except (ExpiredSignatureError, InvalidTokenError):
        return None

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def get_client_ip():
    """Get real client IP address."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def log_audit(action, details, user_id=None, ip=None):
    """Log audit event."""
    if ip is None:
        ip = get_client_ip()
    audit_logger.info(
        f"ACTION={action} | USER_ID={user_id} | IP={ip} | DETAILS={json.dumps(details)}"
    )

# =========================
# PASSWORD VALIDATION
# =========================
def validate_password_strength(password):
    """
    Validate password strength.
    Returns: (is_valid, message, score)
    """
    score = 0
    messages = []

    if len(password) < 8:
        messages.append("Password must be at least 8 characters long")
    else:
        score += 1

    if len(password) >= 12:
        score += 1

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        messages.append("Password must contain at least one uppercase letter")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        messages.append("Password must contain at least one lowercase letter")

    if re.search(r'\d', password):
        score += 1
    else:
        messages.append("Password must contain at least one digit")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        messages.append("Password must contain at least one special character")

    is_valid = len(messages) == 0
    strength = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'][min(score, 5)]

    return is_valid, "; ".join(messages) if messages else "Password is strong", strength

# =========================
# DATABASE MANAGER
# =========================
class DatabaseManager:
    """Thread-safe database manager with connection pooling."""

    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DATABASE_PATH
        self.local = threading.local()
        self.init_db()

    def get_connection(self):
        """Get thread-local database connection."""
        if not hasattr(self.local, 'connection') or self.local.connection is None:
            self.local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.local.connection.row_factory = sqlite3.Row
        return self.local.connection

    def init_db(self):
        """Initialize database with all required tables."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT DEFAULT 'user' CHECK(role IN ('user', 'pentester', 'admin')),
                is_active BOOLEAN DEFAULT 1,
                is_verified BOOLEAN DEFAULT 0,
                mfa_secret TEXT,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                api_key TEXT UNIQUE,
                api_key_expires TIMESTAMP
            )
        ''')

        # Audit history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                audit_id TEXT UNIQUE NOT NULL,
                target_url TEXT NOT NULL,
                target_domain TEXT,
                scan_type TEXT DEFAULT 'full',
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                compliance_score REAL DEFAULT 0,
                security_score REAL DEFAULT 0,
                performance_score REAL DEFAULT 0,
                grade TEXT,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
                report_path TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                duration_seconds INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        # Audit findings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
                title TEXT NOT NULL,
                description TEXT,
                remediation TEXT,
                cvss_score REAL,
                cwe_id TEXT,
                owasp_category TEXT,
                evidence TEXT,
                url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(audit_id) REFERENCES audit_history(audit_id) ON DELETE CASCADE
            )
        ''')

        # Login attempts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip_address TEXT NOT NULL,
                success BOOLEAN DEFAULT 0,
                failure_reason TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Threat intelligence cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE NOT NULL,
                indicator_type TEXT NOT NULL,
                threat_data TEXT NOT NULL,
                confidence INTEGER DEFAULT 0,
                source TEXT,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # API keys
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                name TEXT,
                permissions TEXT DEFAULT 'read',
                is_active BOOLEAN DEFAULT 1,
                last_used TIMESTAMP,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_history(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_history(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_audit ON audit_findings(audit_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threat_intel_cache(indicator)')

        conn.commit()
        logger.info("Database initialized successfully")

    def create_user(self, username, password, email, role='user'):
        """Create new user with validation."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Sanitize inputs
        username = sanitize_input(username, 50)
        email = sanitize_input(email, 255).lower()

        # Validate email
        if not validate_email(email):
            return None, "Invalid email format"

        # Validate password
        is_valid, msg, strength = validate_password_strength(password)
        if not is_valid:
            return None, msg

        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            return None, "Username or email already exists"

        # Hash password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
        api_key = generate_secure_token(32)

        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role, api_key)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, email, role, api_key))
            conn.commit()
            user_id = cursor.lastrowid
            logger.info(f"User created: {username} (ID: {user_id})")
            return user_id, "User created successfully"
        except sqlite3.IntegrityError:
            return None, "Username or email already exists"

    def verify_user(self, username, password, ip_address=None):
        """Verify user credentials with brute force protection."""
        conn = self.get_connection()
        cursor = conn.cursor()

        username = sanitize_input(username, 50)

        # Check login attempts
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts 
            WHERE username = ? AND success = 0 AND created_at > datetime('now', '-15 minutes')
        ''', (username,))
        failed_attempts = cursor.fetchone()[0]

        if failed_attempts >= 5:
            log_audit('LOGIN_BLOCKED', {'username': username, 'reason': 'too_many_attempts'}, ip=ip_address)
            return None, "Account temporarily locked due to too many failed attempts. Please try again in 15 minutes."

        # Get user
        cursor.execute('''
            SELECT id, username, password_hash, email, role, is_active, 
                   failed_login_attempts, locked_until, api_key
            FROM users WHERE username = ? COLLATE NOCASE
        ''', (username,))
        user = cursor.fetchone()

        if not user:
            # Log failed attempt
            cursor.execute('''
                INSERT INTO login_attempts (username, ip_address, success, failure_reason)
                VALUES (?, ?, 0, 'user_not_found')
            ''', (username, ip_address))
            conn.commit()
            return None, "Invalid credentials"

        # Check if locked
        if user['locked_until'] and datetime.datetime.now() < datetime.datetime.fromisoformat(user['locked_until']):
            return None, "Account is temporarily locked"

        # Check if active
        if not user['is_active']:
            cursor.execute('''
                INSERT INTO login_attempts (username, ip_address, success, failure_reason)
                VALUES (?, ?, 0, 'account_disabled')
            ''', (username, ip_address))
            conn.commit()
            return None, "Account is disabled"

        # Verify password
        if not check_password_hash(user['password_hash'], password):
            # Increment failed attempts
            cursor.execute('''
                UPDATE users SET failed_login_attempts = failed_login_attempts + 1
                WHERE id = ?
            ''', (user['id'],))

            # Lock account after 5 failed attempts
            if user['failed_login_attempts'] + 1 >= 5:
                lock_time = datetime.datetime.now() + datetime.timedelta(minutes=30)
                cursor.execute('''
                    UPDATE users SET locked_until = ? WHERE id = ?
                ''', (lock_time.isoformat(), user['id']))

            cursor.execute('''
                INSERT INTO login_attempts (username, ip_address, success, failure_reason)
                VALUES (?, ?, 0, 'invalid_password')
            ''', (username, ip_address))
            conn.commit()

            log_audit('LOGIN_FAILED', {'username': username}, user_id=user['id'], ip=ip_address)
            return None, "Invalid credentials"

        # Success - reset failed attempts and update last login
        cursor.execute('''
            UPDATE users SET 
                failed_login_attempts = 0,
                locked_until = NULL,
                last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (user['id'],))

        cursor.execute('''
            INSERT INTO login_attempts (username, ip_address, success)
            VALUES (?, ?, 1)
        ''', (username, ip_address))
        conn.commit()

        log_audit('LOGIN_SUCCESS', {'username': username}, user_id=user['id'], ip=ip_address)

        return {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'api_key': user['api_key']
        }, "Login successful"

    def get_user_by_api_key(self, api_key):
        """Get user by API key."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, username, email, role, is_active FROM users 
            WHERE api_key = ? AND is_active = 1
        ''', (api_key,))
        user = cursor.fetchone()

        if user:
            return dict(user)
        return None

    def save_audit_result(self, user_id, audit_data):
        """Save audit result to database."""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO audit_history (
                    user_id, audit_id, target_url, target_domain, scan_type,
                    total_findings, critical_count, high_count, medium_count,
                    low_count, info_count, compliance_score, security_score,
                    performance_score, grade, status, report_path,
                    duration_seconds, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                audit_data.get('audit_id'),
                audit_data.get('target_url'),
                audit_data.get('target_domain'),
                audit_data.get('scan_type', 'full'),
                audit_data.get('total_findings', 0),
                audit_data.get('critical_count', 0),
                audit_data.get('high_count', 0),
                audit_data.get('medium_count', 0),
                audit_data.get('low_count', 0),
                audit_data.get('info_count', 0),
                audit_data.get('compliance_score', 0),
                audit_data.get('security_score', 0),
                audit_data.get('performance_score', 0),
                audit_data.get('grade'),
                audit_data.get('status', 'completed'),
                audit_data.get('report_path'),
                audit_data.get('duration_seconds'),
                audit_data.get('ip_address'),
                audit_data.get('user_agent')
            ))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error saving audit: {e}")
            conn.rollback()
            return None

    def get_user_audit_history(self, user_id, limit=20, offset=0):
        """Get user's audit history."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM audit_history 
            WHERE user_id = ? 
            ORDER BY started_at DESC 
            LIMIT ? OFFSET ?
        ''', (user_id, limit, offset))

        return [dict(row) for row in cursor.fetchall()]

    def cache_threat_intel(self, indicator, indicator_type, threat_data, confidence=0, expires_hours=24):
        """Cache threat intelligence data."""
        conn = self.get_connection()
        cursor = conn.cursor()

        expires_at = datetime.datetime.now() + datetime.timedelta(hours=expires_hours)

        cursor.execute('''
            INSERT OR REPLACE INTO threat_intel_cache 
            (indicator, indicator_type, threat_data, confidence, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (indicator, indicator_type, json.dumps(threat_data), confidence, expires_at.isoformat()))
        conn.commit()

    def get_cached_threat(self, indicator):
        """Get cached threat intelligence."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM threat_intel_cache 
            WHERE indicator = ? AND expires_at > datetime('now')
        ''', (indicator,))

        result = cursor.fetchone()
        if result:
            data = dict(result)
            data['threat_data'] = json.loads(data['threat_data'])
            return data
        return None

# Initialize database manager
db_manager = DatabaseManager()

# =========================
# SECURITY SCANNER
# =========================
class SecurityScanner:
    """Comprehensive security scanner with multiple checks."""

    def __init__(self, target_url, audit_id):
        self.target_url = target_url
        self.audit_id = audit_id
        self.domain = urlparse(target_url).netloc
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecurityAnalyzer/3.0 (Security Scanning Bot)'
        })
        self.session.timeout = Config.SCAN_TIMEOUT

    def add_finding(self, finding_type, severity, title, description, 
                    remediation=None, cvss_score=None, cwe_id=None, 
                    owasp_category=None, evidence=None, url=None):
        """Add a security finding."""
        self.findings.append({
            'finding_type': finding_type,
            'severity': severity,
            'title': title,
            'description': description,
            'remediation': remediation,
            'cvss_score': cvss_score,
            'cwe_id': cwe_id,
            'owasp_category': owasp_category,
            'evidence': evidence,
            'url': url or self.target_url,
            'timestamp': datetime.datetime.now().isoformat()
        })

    def check_xss(self):
        """Check for Cross-Site Scripting vulnerabilities."""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '\">\'<script>alert(String.fromCharCode(88,83,83))</script>',
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ]

        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, "html.parser")

            # Check for reflected XSS in forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')

                for inp in inputs:
                    name = inp.get('name', '')
                    if name:
                        test_url = f"{self.target_url}?{name}={xss_payloads[0]}"
                        try:
                            test_resp = self.session.get(test_url, timeout=5)
                            if xss_payloads[0] in test_resp.text:
                                self.add_finding(
                                    'xss_reflected', 'high',
                                    f'Reflected XSS in parameter: {name}',
                                    f'The parameter "{name}" reflects user input without proper sanitization.',
                                    'Implement input validation and output encoding. Use Content Security Policy.',
                                    6.1, 'CWE-79', 'A03:2021 - Injection',
                                    f'Payload reflected: {xss_payloads[0][:50]}...',
                                    test_url
                                )
                                break
                        except Exception:
                            pass

            # Check for DOM-based XSS
            scripts = soup.find_all('script')
            dangerous_patterns = [
                'document.write',
                'innerHTML',
                'eval(',
                'setTimeout(',
                'setInterval(',
                'location.href',
                'location.replace'
            ]
            for script in scripts:
                script_text = script.string if script.string else ''
                for pattern in dangerous_patterns:
                    if pattern in script_text:
                        self.add_finding(
                            'xss_dom', 'medium',
                            f'Potential DOM-based XSS: {pattern}',
                            f'Dangerous JavaScript pattern "{pattern}" detected.',
                            'Avoid using dangerous DOM manipulation methods with user input.',
                            5.4, 'CWE-79', 'A03:2021 - Injection',
                            pattern
                        )

            # Check for stored XSS indicators
            if soup.find_all(text=re.compile(r'<script')):
                self.add_finding(
                    'xss_stored', 'critical',
                    'Potential Stored XSS detected',
                    'Script tags found in page content, indicating potential stored XSS.',
                    'Implement strict input validation and output encoding.',
                    8.2, 'CWE-79', 'A03:2021 - Injection'
                )

        except Exception as e:
            logger.error(f"XSS check error: {e}")

    def check_sql_injection(self):
        """Check for SQL Injection vulnerabilities."""
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' AND 1=1 --",
            "1' AND 1=2 --",
            "1; DROP TABLE users --",
            "1 UNION SELECT null, null, null --",
            "1' AND SLEEP(5) --",
            "1' AND pg_sleep(5) --",
            "1 WAITFOR DELAY '0:0:5' --",
        ]

        error_patterns = [
            'sql syntax',
            'mysql_fetch',
            'pg_query',
            'ORA-',
            'SQL Server',
            'ODBC Error',
            'SQLite3::',
            'syntax error',
            'unterminated',
            'unexpected'
        ]

        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    name = inp.get('name', '')
                    if name:
                        for payload in sql_payloads[:5]:
                            test_url = f"{self.target_url}?{name}={payload}"
                            try:
                                test_resp = self.session.get(test_url, timeout=5)
                                content = test_resp.text.lower()
                                for pattern in error_patterns:
                                    if pattern.lower() in content:
                                        self.add_finding(
                                            'sql_injection', 'critical',
                                            f'SQL Injection in parameter: {name}',
                                            f'Database error detected when testing parameter "{name}".',
                                            'Use parameterized queries/prepared statements. Implement input validation.',
                                            9.8, 'CWE-89', 'A03:2021 - Injection',
                                            f'Error pattern: {pattern}',
                                            test_url
                                        )
                                        return
                            except Exception:
                                pass

            # Check URL parameters
            parsed = urlparse(self.target_url)
            if parsed.query:
                for payload in sql_payloads[:3]:
                    test_url = self.target_url + payload
                    try:
                        test_resp = self.session.get(test_url, timeout=5)
                        content = test_resp.text.lower()
                        for pattern in error_patterns:
                            if pattern.lower() in content:
                                self.add_finding(
                                    'sql_injection', 'critical',
                                    'SQL Injection in URL parameters',
                                    'Database error detected in URL parameters.',
                                    'Use parameterized queries. Validate all input.',
                                    9.8, 'CWE-89', 'A03:2021 - Injection',
                                    f'Error pattern: {pattern}'
                                )
                                return
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"SQL injection check error: {e}")

    def check_security_headers(self):
        """Check HTTP security headers."""
        required_headers = {
            'Strict-Transport-Security': ('HSTS', 'high', 6.5, 'CWE-319', 'A02:2021 - Cryptographic Failures'),
            'Content-Security-Policy': ('CSP', 'high', 6.5, 'CWE-693', 'A05:2021 - Security Misconfiguration'),
            'X-Frame-Options': ('Clickjacking Protection', 'medium', 5.4, 'CWE-1021', 'A01:2021 - Broken Access Control'),
            'X-Content-Type-Options': ('MIME Sniffing Protection', 'medium', 5.3, 'CWE-693', 'A05:2021 - Security Misconfiguration'),
            'Referrer-Policy': ('Referrer Policy', 'low', 3.7, 'CWE-200', 'A01:2021 - Broken Access Control'),
            'Permissions-Policy': ('Permissions Policy', 'low', 3.5, 'CWE-693', 'A05:2021 - Security Misconfiguration'),
        }

        try:
            response = self.session.get(self.target_url)
            headers = response.headers

            for header, (name, severity, cvss, cwe, owasp) in required_headers.items():
                if header not in headers:
                    self.add_finding(
                        'missing_header', severity,
                        f'Missing Security Header: {header}',
                        f'The {name} header is not set. This reduces the security posture of the application.',
                        f'Add the {header} header with appropriate values.',
                        cvss, cwe, owasp
                    )

            # Check for information disclosure headers
            info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in info_headers:
                if header in headers:
                    self.add_finding(
                        'info_disclosure', 'low',
                        f'Information Disclosure: {header}',
                        f'The {header} header reveals server information.',
                        f'Remove or obfuscate the {header} header.',
                        3.5, 'CWE-200', 'A01:2021 - Broken Access Control',
                        f'{header}: {headers.get(header)}'
                    )

            # Check for insecure cookies
            if 'Set-Cookie' in headers:
                cookie = headers.get('Set-Cookie', '')
                if 'Secure' not in cookie:
                    self.add_finding(
                        'insecure_cookie', 'high',
                        'Cookie without Secure flag',
                        'Cookies are not transmitted over HTTPS only.',
                        'Set the Secure flag on all cookies.',
                        6.5, 'CWE-614', 'A02:2021 - Cryptographic Failures',
                        cookie[:100]
                    )
                if 'HttpOnly' not in cookie:
                    self.add_finding(
                        'insecure_cookie', 'high',
                        'Cookie without HttpOnly flag',
                        'Cookies are accessible via JavaScript.',
                        'Set the HttpOnly flag on all cookies.',
                        6.5, 'CWE-1004', 'A02:2021 - Cryptographic Failures',
                        cookie[:100]
                    )
                if 'SameSite' not in cookie:
                    self.add_finding(
                        'insecure_cookie', 'medium',
                        'Cookie without SameSite attribute',
                        'Cookies are vulnerable to CSRF attacks.',
                        'Set the SameSite attribute on all cookies.',
                        5.4, 'CWE-1275', 'A01:2021 - Broken Access Control',
                        cookie[:100]
                    )

        except Exception as e:
            logger.error(f"Security headers check error: {e}")

    def check_open_ports(self):
        """Check for commonly exposed ports."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        open_ports = []

        try:
            ip = socket.getaddrinfo(self.domain, None)[0][4][0]

            with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
                future_to_port = {
                    executor.submit(self._check_port, ip, port): port 
                    for port in common_ports
                }
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        if future.result():
                            open_ports.append(port)
                    except Exception:
                        pass

            if open_ports:
                for port in open_ports:
                    service = self._get_service_name(port)
                    severity = 'high' if port in [21, 23, 445, 3389] else 'medium'
                    cvss = 7.5 if severity == 'high' else 5.3

                    self.add_finding(
                        'open_port', severity,
                        f'Open Port Detected: {port}/{service}',
                        f'Port {port} ({service}) is open and potentially accessible.',
                        'Close unnecessary ports or restrict access with firewall rules.',
                        cvss, 'CWE-284', 'A01:2021 - Broken Access Control',
                        f'Port {port} open on {ip}'
                    )

        except Exception as e:
            logger.error(f"Port scan error: {e}")

    def _check_port(self, ip, port):
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _get_service_name(self, port):
        """Get service name for port."""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')

    def check_sensitive_files(self):
        """Check for exposed sensitive files."""
        sensitive_paths = [
            '/.env', '/.git/config', '/.htaccess', '/.htpasswd',
            '/config.php', '/wp-config.php', '/config.json',
            '/robots.txt', '/sitemap.xml', '/.DS_Store',
            '/phpinfo.php', '/info.php', '/server-status',
            '/.well-known/security.txt', '/api/swagger.json',
            '/api/docs', '/swagger-ui.html', '/v2/api-docs',
            '/actuator/health', '/actuator/env', '/actuator',
            '/debug', '/console', '/admin', '/phpmyadmin',
            '/.svn/entries', '/.git/HEAD', '/.hg',
            '/backup.sql', '/database.sql', '/dump.sql',
            '/.env.local', '/.env.production', '/.env.development',
        ]

        try:
            for path in sensitive_paths:
                try:
                    url = urljoin(self.target_url, path)
                    response = self.session.get(url, timeout=5, allow_redirects=False)

                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        content_length = len(response.text)

                        if content_length > 0:
                            severity = 'high' if any(x in path for x in ['.env', 'config', 'backup', 'dump']) else 'medium'
                            cvss = 7.5 if severity == 'high' else 5.3

                            self.add_finding(
                                'sensitive_file', severity,
                                f'Exposed Sensitive File: {path}',
                                f'Sensitive file {path} is publicly accessible.',
                                'Remove or restrict access to sensitive files.',
                                cvss, 'CWE-538', 'A05:2021 - Security Misconfiguration',
                                f'Content-Type: {content_type}, Size: {content_length} bytes',
                                url
                            )
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Sensitive files check error: {e}")

    def check_ssl_tls(self):
        """Check SSL/TLS configuration."""
        if not self.target_url.startswith('https'):
            self.add_finding(
                'no_https', 'critical',
                'HTTPS Not Enabled',
                'The website does not use HTTPS, allowing traffic interception.',
                'Enable HTTPS and redirect HTTP to HTTPS.',
                8.2, 'CWE-319', 'A02:2021 - Cryptographic Failures'
            )
            return

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check SSL/TLS version
                    if version in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                        self.add_finding(
                            'weak_ssl', 'high',
                            f'Weak SSL/TLS Version: {version}',
                            f'The server supports {version} which has known vulnerabilities.',
                            'Disable weak protocols and enable TLS 1.2 or higher only.',
                            7.5, 'CWE-326', 'A02:2021 - Cryptographic Failures',
                            f'Protocol: {version}'
                        )

                    # Check certificate expiration
                    if cert and 'notAfter' in cert:
                        expiry = cert['notAfter']
                        try:
                            expiry_date = datetime.datetime.strptime(expiry, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry_date - datetime.datetime.now()).days
                            if days_until_expiry < 30:
                                self.add_finding(
                                    'cert_expiry', 'medium',
                                    'SSL Certificate Expiring Soon',
                                    f'SSL certificate expires in {days_until_expiry} days.',
                                    'Renew the SSL certificate before expiration.',
                                    5.3, 'CWE-298', 'A02:2021 - Cryptographic Failures',
                                    f'Expires: {expiry}'
                                )
                        except Exception:
                            pass

                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                    if cipher and any(wc in str(cipher) for wc in weak_ciphers):
                        self.add_finding(
                            'weak_cipher', 'high',
                            'Weak Cipher Suite',
                            'The server supports weak cipher suites.',
                            'Disable weak ciphers and use strong cipher suites only.',
                            7.5, 'CWE-326', 'A02:2021 - Cryptographic Failures',
                            f'Cipher: {cipher}'
                        )

        except Exception as e:
            logger.error(f"SSL check error: {e}")

    def check_csrf(self):
        """Check for CSRF protection."""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all('form')

            for form in forms:
                if form.get('method', 'get').lower() == 'post':
                    csrf_input = form.find('input', {'name': re.compile(r'csrf', re.I)})
                    if not csrf_input:
                        self.add_finding(
                            'csrf', 'medium',
                            'Missing CSRF Protection',
                            'Form submission lacks CSRF token protection.',
                            'Implement CSRF tokens for all state-changing operations.',
                            6.5, 'CWE-352', 'A01:2021 - Broken Access Control',
                            str(form)[:200]
                        )
                        break

        except Exception as e:
            logger.error(f"CSRF check error: {e}")

    def check_ssrf(self):
        """Check for SSRF vulnerabilities."""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, "html.parser")

            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    input_type = inp.get('type', '')
                    name = inp.get('name', '').lower()
                    if input_type == 'url' or any(x in name for x in ['url', 'link', 'path', 'file', 'redirect']):
                        self.add_finding(
                            'ssrf_potential', 'medium',
                            f'Potential SSRF Vector: {name}',
                            f'Input field "{name}" accepts URLs which may be vulnerable to SSRF.',
                            'Validate and sanitize all URL inputs. Block internal/private IP ranges.',
                            5.3, 'CWE-918', 'A10:2021 - Server-Side Request Forgery',
                            f'Input name: {name}'
                        )

        except Exception as e:
            logger.error(f"SSRF check error: {e}")

    def check_idor(self):
        """Check for Insecure Direct Object Reference."""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, "html.parser")

            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                if re.search(r'[?&](id|user_id|file_id|doc_id)=\d+', href):
                    self.add_finding(
                        'idor', 'medium',
                        'Potential IDOR Vulnerability',
                        'Predictable numeric IDs detected in URLs.',
                        'Use unpredictable identifiers (UUIDs) and implement authorization checks.',
                        5.3, 'CWE-639', 'A01:2021 - Broken Access Control',
                        href
                    )
                    break

        except Exception as e:
            logger.error(f"IDOR check error: {e}")

    def run_all_checks(self):
        """Run all security checks."""
        checks = [
            ('Security Headers', self.check_security_headers),
            ('SSL/TLS', self.check_ssl_tls),
            ('XSS', self.check_xss),
            ('SQL Injection', self.check_sql_injection),
            ('CSRF', self.check_csrf),
            ('SSRF', self.check_ssrf),
            ('IDOR', self.check_idor),
            ('Open Ports', self.check_open_ports),
            ('Sensitive Files', self.check_sensitive_files),
        ]

        for name, check_func in checks:
            try:
                logger.info(f"Running check: {name}")
                check_func()
            except Exception as e:
                logger.error(f"Error in {name} check: {e}")

        return self.findings

# =========================
# SUBDOMAIN SCANNER
# =========================
class SubdomainScanner:
    """Subdomain enumeration scanner."""

    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news',
            'vpn', 'ns4', 'www1', 'new', 'mysql', 'old', 'lists', 'support',
            'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
            'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images',
            'img', 'www3', 'staging', 'www4', 'www5', 'video', 'vip', 'cdn',
            'api', 'app', 'uat', 'prod', 'production', 'internal', 'private',
            'secret', 'root', 'user', 'login', 'auth', 'oauth', 'sso', 'idp',
            'saml', 'ldap', 'ad', 'dc', 'jenkins', 'gitlab', 'github', 'svn',
            'grafana', 'prometheus', 'kibana', 'elasticsearch', 'logstash',
            'docker', 'kubernetes', 'k8s', 'rancher', 'openshift',
            'db', 'database', 'postgres', 'mongo', 'redis', 'backup',
            'archive', 'dump', 'bak', 'temp', 'tmp', 'api-v1', 'api-v2',
            'api-v3', 'graphql', 'rest', 'soap', 'ws', 'websocket',
            'socket', 'io', 'realtime', 'assets', 'css', 'js', 'files',
            'uploads', 'download', 'storage', 's3', 'blob', 'meet',
            'zoom', 'teams', 'slack', 'chat', 'help', 'ticket', 'crm',
            'sales', 'marketing', 'analytics', 'stats', 'metrics',
            'monitoring', 'health', 'status', 'ping', 'probe', 'check',
            'debug', 'console', 'admin', 'superadmin', 'root', 'master'
        ]

    def enumerate(self, max_workers=20):
        """Enumerate subdomains using DNS resolution."""
        found = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subdomain = {
                executor.submit(self._check_subdomain, sub): sub 
                for sub in self.wordlist
            }
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        found.append(subdomain)
                except Exception:
                    pass

        self.subdomains = found
        return found

    def _check_subdomain(self, subdomain):
        """Check if subdomain exists."""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            socket.gethostbyname(full_domain)
            return True
        except socket.gaierror:
            return False

# =========================
# COMPLIANCE CHECKER
# =========================
class ComplianceChecker:
    """Security compliance checker for various standards."""

    def __init__(self):
        self.results = {}

    def check_all(self, findings, headers, ssl_info):
        """Run all compliance checks."""
        self.results['pci_dss'] = self.check_pci_dss(findings, headers, ssl_info)
        self.results['hipaa'] = self.check_hipaa(findings, headers, ssl_info)
        self.results['gdpr'] = self.check_gdpr(findings, headers, ssl_info)
        self.results['soc2'] = self.check_soc2(findings, headers, ssl_info)
        self.results['iso27001'] = self.check_iso27001(findings, headers, ssl_info)
        self.results['owasp_top10'] = self.check_owasp_top10(findings)
        return self.results

    def check_pci_dss(self, findings, headers, ssl_info):
        """Check PCI DSS compliance."""
        checks = {
            'https_required': headers.get('url', '').startswith('https'),
            'hsts_enabled': 'Strict-Transport-Security' in headers,
            'secure_cookies': 'Secure' in str(headers.get('Set-Cookie', '')),
            'no_ssl_errors': not any(f['finding_type'] == 'weak_ssl' for f in findings),
            'no_info_disclosure': not any(f['finding_type'] == 'info_disclosure' for f in findings),
            'input_validation': not any(f['finding_type'] in ['sql_injection', 'xss_reflected'] for f in findings),
            'access_control': not any(f['finding_type'] == 'idor' for f in findings),
        }
        score = sum(checks.values()) / len(checks) * 100
        return {'compliant': score >= 80, 'score': round(score, 2), 'checks': checks}

    def check_hipaa(self, findings, headers, ssl_info):
        """Check HIPAA compliance."""
        checks = {
            'encryption_in_transit': headers.get('url', '').startswith('https'),
            'access_control': not any(f['finding_type'] == 'idor' for f in findings),
            'audit_logging': True,
            'integrity': not any(f['finding_type'] == 'sql_injection' for f in findings),
            'authentication': not any(f['finding_type'] == 'missing_header' for f in findings),
            'data_encryption': not any(f['finding_type'] == 'no_https' for f in findings),
        }
        score = sum(checks.values()) / len(checks) * 100
        return {'compliant': score >= 80, 'score': round(score, 2), 'checks': checks}

    def check_gdpr(self, findings, headers, ssl_info):
        """Check GDPR compliance."""
        checks = {
            'data_protection': headers.get('url', '').startswith('https'),
            'privacy_by_design': 'Privacy' in str(headers),
            'security_headers': all(h in headers for h in ['X-Frame-Options', 'X-Content-Type-Options']),
            'no_tracking': 'DNT' in str(headers) or 'Global-Privacy-Control' in str(headers),
            'data_minimization': not any(f['finding_type'] == 'info_disclosure' for f in findings),
            'breach_notification': True,
        }
        score = sum(checks.values()) / len(checks) * 100
        return {'compliant': score >= 80, 'score': round(score, 2), 'checks': checks}

    def check_soc2(self, findings, headers, ssl_info):
        """Check SOC 2 compliance."""
        checks = {
            'security': not any(f['severity'] == 'critical' for f in findings),
            'availability': True,
            'processing_integrity': not any(f['finding_type'] == 'sql_injection' for f in findings),
            'confidentiality': headers.get('url', '').startswith('https'),
            'privacy': not any(f['finding_type'] == 'info_disclosure' for f in findings),
        }
        score = sum(checks.values()) / len(checks) * 100
        return {'compliant': score >= 80, 'score': round(score, 2), 'checks': checks}

    def check_iso27001(self, findings, headers, ssl_info):
        """Check ISO 27001 compliance."""
        checks = {
            'risk_assessment': True,
            'security_policy': True,
            'access_control': not any(f['finding_type'] == 'idor' for f in findings),
            'cryptography': headers.get('url', '').startswith('https'),
            'physical_security': True,
            'operations_security': not any(f['finding_type'] == 'open_port' for f in findings),
            'communications_security': not any(f['finding_type'] == 'weak_ssl' for f in findings),
        }
        score = sum(checks.values()) / len(checks) * 100
        return {'compliant': score >= 80, 'score': round(score, 2), 'checks': checks}

    def check_owasp_top10(self, findings):
        """Check OWASP Top 10 coverage."""
        owasp_categories = {
            'A01:2021 - Broken Access Control': ['idor', 'missing_auth'],
            'A02:2021 - Cryptographic Failures': ['weak_ssl', 'no_https', 'insecure_cookie'],
            'A03:2021 - Injection': ['sql_injection', 'xss_reflected', 'xss_stored', 'xss_dom'],
            'A04:2021 - Insecure Design': ['csrf', 'ssrf_potential'],
            'A05:2021 - Security Misconfiguration': ['missing_header', 'info_disclosure', 'open_port', 'sensitive_file'],
            'A06:2021 - Vulnerable Components': [],
            'A07:2021 - Identification and Authentication Failures': [],
            'A08:2021 - Software and Data Integrity Failures': [],
            'A09:2021 - Security Logging and Monitoring Failures': [],
            'A10:2021 - Server-Side Request Forgery': ['ssrf_potential'],
        }

        results = {}
        for category, types in owasp_categories.items():
            found = any(f['finding_type'] in types for f in findings)
            results[category] = {
                'found': found, 
                'count': sum(1 for f in findings if f['finding_type'] in types)
            }

        return results

# =========================
# THREAT INTELLIGENCE
# =========================
class ThreatIntelligence:
    """Threat intelligence checker."""

    def __init__(self):
        self.cache = {}

    def check_ip_reputation(self, ip_address):
        """Check IP reputation using multiple sources."""
        cached = db_manager.get_cached_threat(ip_address)
        if cached:
            return cached['threat_data']

        result = {
            'ip': ip_address,
            'reputation': 'unknown',
            'threat_score': 0,
            'categories': [],
            'sources': []
        }

        if is_private_ip(ip_address):
            result['reputation'] = 'private'
            result['categories'].append('Private IP Range')
            return result

        abuse_key = os.environ.get('ABUSEIPDB_API_KEY')
        if abuse_key:
            try:
                headers = {'Key': abuse_key, 'Accept': 'application/json'}
                resp = requests.get(
                    f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}',
                    headers=headers, timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json().get('data', {})
                    result['threat_score'] = data.get('abuseConfidenceScore', 0)
                    if result['threat_score'] > 50:
                        result['reputation'] = 'malicious'
                    elif result['threat_score'] > 25:
                        result['reputation'] = 'suspicious'
                    else:
                        result['reputation'] = 'clean'
                    result['categories'] = data.get('usageType', [])
                    result['sources'].append('AbuseIPDB')
            except Exception as e:
                logger.error(f"AbuseIPDB check error: {e}")

        db_manager.cache_threat_intel(ip_address, 'ip', result, expires_hours=24)
        return result

    def get_domain_reputation(self, domain):
        """Get domain reputation."""
        cached = db_manager.get_cached_threat(domain)
        if cached:
            return cached['threat_data']

        result = {
            'domain': domain,
            'reputation': 'unknown',
            'threat_score': 0,
            'categories': [],
            'sources': [],
            'ip_addresses': [],
            'mx_records': [],
            'spf': False,
            'dkim': False,
            'dmarc': False
        }

        try:
            answers = dns.resolver.resolve(domain, 'A')
            result['ip_addresses'] = [str(rdata) for rdata in answers]
        except Exception:
            pass

        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(rdata.exchange) for rdata in answers]
        except Exception:
            pass

        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            txt_records = [str(rdata) for rdata in answers]
            result['spf'] = any('v=spf1' in r for r in txt_records)
            result['dkim'] = any('DKIM' in r for r in txt_records)
            result['dmarc'] = any('v=DMARC1' in r for r in txt_records)
        except Exception:
            result['spf'] = False
            result['dkim'] = False
            result['dmarc'] = False

        db_manager.cache_threat_intel(domain, 'domain', result, expires_hours=24)
        return result

# =========================
# PDF REPORT GENERATOR
# =========================
class PDFReportGenerator:
    """Generate professional PDF security reports."""

    def __init__(self, audit_data):
        self.audit_data = audit_data
        self.styles = getSampleStyleSheet()
        self.custom_styles = {
            'Title': ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a2e'),
                spaceAfter=30,
                alignment=1
            ),
            'Section': ParagraphStyle(
                'CustomSection',
                parent=self.styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#16213e'),
                spaceAfter=12,
                spaceBefore=12
            ),
            'Finding': ParagraphStyle(
                'CustomFinding',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#333333'),
                spaceAfter=6
            ),
            'Critical': ParagraphStyle(
                'CriticalFinding',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#dc3545'),
                spaceAfter=6
            ),
            'High': ParagraphStyle(
                'HighFinding',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#fd7e14'),
                spaceAfter=6
            ),
            'Medium': ParagraphStyle(
                'MediumFinding',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#ffc107'),
                spaceAfter=6
            ),
            'Low': ParagraphStyle(
                'LowFinding',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#28a745'),
                spaceAfter=6
            ),
        }

    def generate(self, output_path=None):
        """Generate PDF report."""
        if not output_path:
            output_path = os.path.join(
                Config.UPLOAD_FOLDER, 
                f"report_{self.audit_data.get('audit_id', 'unknown')}.pdf"
            )

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        story = []

        # Title
        story.append(Paragraph("Security Assessment Report", self.custom_styles['Title']))
        story.append(Spacer(1, 20))

        # Executive Summary
        story.append(Paragraph("Executive Summary", self.custom_styles['Section']))
        summary_data = [
            ['Target URL', self.audit_data.get('target_url', 'N/A')],
            ['Scan Date', self.audit_data.get('scan_date', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))],
            ['Total Findings', str(self.audit_data.get('total_findings', 0))],
            ['Critical', str(self.audit_data.get('critical_count', 0))],
            ['High', str(self.audit_data.get('high_count', 0))],
            ['Medium', str(self.audit_data.get('medium_count', 0))],
            ['Low', str(self.audit_data.get('low_count', 0))],
            ['Security Score', f"{self.audit_data.get('security_score', 0)}/100"],
            ['Grade', self.audit_data.get('grade', 'N/A')],
        ]

        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Findings
        if self.audit_data.get('findings'):
            story.append(Paragraph("Detailed Findings", self.custom_styles['Section']))
            for finding in self.audit_data['findings']:
                severity = finding.get('severity', 'info').capitalize()
                style_name = severity if severity in self.custom_styles else 'Finding'

                story.append(Paragraph(
                    f"[{severity}] {finding.get('title', 'Untitled')}",
                    self.custom_styles[style_name]
                ))
                story.append(Paragraph(
                    f"Type: {finding.get('finding_type', 'N/A')} | "
                    f"CVSS: {finding.get('cvss_score', 'N/A')} | "
                    f"CWE: {finding.get('cwe_id', 'N/A')}",
                    self.styles['Normal']
                ))
                story.append(Paragraph(
                    f"Description: {finding.get('description', 'N/A')}",
                    self.styles['Normal']
                ))
                if finding.get('remediation'):
                    story.append(Paragraph(
                        f"Remediation: {finding['remediation']}",
                        self.styles['Normal']
                    ))
                story.append(Spacer(1, 10))

        # Compliance
        if self.audit_data.get('compliance'):
            story.append(PageBreak())
            story.append(Paragraph("Compliance Assessment", self.custom_styles['Section']))
            for standard, result in self.audit_data['compliance'].items():
                status = "Compliant" if result.get('compliant') else "Non-Compliant"
                story.append(Paragraph(
                    f"{standard.upper()}: {status} (Score: {result.get('score', 0)}%)",
                    self.styles['Normal']
                ))

        doc.build(story)
        return output_path

# =========================
# EMAIL NOTIFIER
# =========================
class EmailNotifier:
    """Email notification system."""

    def __init__(self):
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.username = Config.SMTP_USERNAME
        self.password = Config.SMTP_PASSWORD
        self.from_email = Config.SMTP_FROM

    def send_audit_complete_email(self, to_email, audit_data, pdf_file=None):
        """Send audit completion email."""
        if not self.username or not self.password:
            logger.warning("SMTP credentials not configured, skipping email")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = f"Security Audit Complete - {audit_data.get('target_url', 'Unknown')}"

            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>Security Audit Complete</h2>
                <p>Your security audit for <strong>{audit_data.get('target_url', 'Unknown')}</strong> has been completed.</p>
                <table style="border-collapse: collapse; width: 100%;">
                    <tr><td style="padding: 8px; border: 1px solid #ddd;">Total Findings</td><td style="padding: 8px; border: 1px solid #ddd;">{audit_data.get('total_findings', 0)}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;">Critical</td><td style="padding: 8px; border: 1px solid #ddd;">{audit_data.get('critical_count', 0)}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;">High</td><td style="padding: 8px; border: 1px solid #ddd;">{audit_data.get('high_count', 0)}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;">Medium</td><td style="padding: 8px; border: 1px solid #ddd;">{audit_data.get('medium_count', 0)}</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;">Security Score</td><td style="padding: 8px; border: 1px solid #ddd;">{audit_data.get('security_score', 0)}/100</td></tr>
                    <tr><td style="padding: 8px; border: 1px solid #ddd;">Grade</td><td style="padding: 8px; border: 1px solid #ddd;">{audit_data.get('grade', 'N/A')}</td></tr>
                </table>
                <p>Please review the attached report for detailed findings and recommendations.</p>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            if pdf_file and os.path.exists(pdf_file):
                with open(pdf_file, 'rb') as f:
                    attachment = MIMEApplication(f.read(), _subtype='pdf')
                    attachment.add_header('Content-Disposition', 'attachment', 
                                        filename=os.path.basename(pdf_file))
                    msg.attach(attachment)

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Audit completion email sent to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            return False

# =========================
# AUTHENTICATION DECORATORS
# =========================
def require_auth(f):
    """Require authentication decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check JWT token first
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            payload = verify_jwt_token(token)
            if payload:
                g.user = payload
                return f(*args, **kwargs)

        # Check session
        if 'pentester_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401

        g.user = {
            'user_id': session.get('pentester_id'),
            'username': session.get('pentester_username'),
            'role': session.get('pentester_role', 'user')
        }
        return f(*args, **kwargs)
    return decorated_function

def require_pentester(f):
    """Require pentester role decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'pentester_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401

        role = session.get('pentester_role', 'user')
        if role not in ('pentester', 'admin'):
            return jsonify({'success': False, 'error': 'Pentester access required'}), 403

        g.user = {
            'user_id': session.get('pentester_id'),
            'username': session.get('pentester_username'),
            'role': role
        }
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Require admin role decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'pentester_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401

        if session.get('pentester_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403

        g.user = {
            'user_id': session.get('pentester_id'),
            'username': session.get('pentester_username'),
            'role': 'admin'
        }
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    """Require API key decorator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({'success': False, 'error': 'API key required'}), 401

        user = db_manager.get_user_by_api_key(api_key)
        if not user:
            return jsonify({'success': False, 'error': 'Invalid API key'}), 401

        g.user = user
        return f(*args, **kwargs)
    return decorated_function

# =========================
# SECURITY HEADERS
# =========================
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    for header, value in Config.SECURITY_HEADERS.items():
        response.headers[header] = value

    # Add cache control for sensitive pages
    if request.path in ['/login', '/register', '/admin']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    return response

# =========================
# ROUTES
# =========================
@app.route("/")
def home():
    """Home page."""
    return render_template("index.html", csrf_token=generate_csrf())

@app.route("/pentest-dashboard")
@require_auth
def pentest_dashboard():
    """Pentest dashboard."""
    return render_template("dashboard.html", csrf_token=generate_csrf())

@app.route("/api/analyze", methods=["POST"])
@limiter.limit("30 per minute")
@require_auth
def analyze():
    """Analyze website security."""
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"success": False, "error": "URL is required"}), 400

        url = data["url"].strip()

        # Validate URL
        if not url.startswith(("http://", "https://")):
            return jsonify({"success": False, "error": "Invalid URL format. Must start with http:// or https://"}), 400

        validated_url = validate_url(url)
        if not validated_url:
            return jsonify({"success": False, "error": "Invalid URL format"}), 400

        # Check for SSRF
        if is_blocked_url(validated_url):
            log_audit('SSRF_BLOCKED', {'url': validated_url}, 
                     user_id=session.get('pentester_id'), ip=get_client_ip())
            return jsonify({"success": False, "error": "URL points to blocked or internal resource"}), 403

        # Perform analysis
        start = time.time()
        try:
            response = requests.get(
                validated_url, 
                timeout=Config.SCAN_TIMEOUT, 
                headers={"User-Agent": "WebSecurityAnalyzer/3.0"},
                allow_redirects=True,
                verify=True
            )
        except requests.exceptions.SSLError:
            return jsonify({"success": False, "error": "SSL certificate verification failed"}), 400
        except requests.exceptions.Timeout:
            return jsonify({"success": False, "error": "Request timed out"}), 408
        except requests.exceptions.ConnectionError:
            return jsonify({"success": False, "error": "Connection error"}), 400
        except Exception as e:
            logger.error(f"Analysis request error: {e}")
            return jsonify({"success": False, "error": "Failed to fetch URL"}), 400

        load_time = round(time.time() - start, 2)
        size_kb = round(len(response.text) / 1024, 2)

        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No title"
        headers = dict(response.headers)

        # Security checks
        security = {
            "https": response.url.startswith("https"),
            "hsts": "Strict-Transport-Security" in headers,
            "csp": "Content-Security-Policy" in headers,
            "x_frame": "X-Frame-Options" in headers,
            "x_content_type": "X-Content-Type-Options" in headers,
            "xss_protection": "X-XSS-Protection" in headers,
            "referrer_policy": "Referrer-Policy" in headers,
            "permissions_policy": "Permissions-Policy" in headers,
        }

        security_score = sum(security.values()) / len(security) * 100

        # Performance scoring
        perf_score = 100
        if load_time > 5: perf_score -= 50
        elif load_time > 3: perf_score -= 30
        elif load_time > 2: perf_score -= 15
        if size_kb > 3000: perf_score -= 20
        elif size_kb > 2000: perf_score -= 10
        perf_score = max(perf_score, 0)

        total_score = (perf_score + security_score) // 2

        # Grade calculation
        grades = [(95, "A+"), (90, "A"), (85, "A-"), (80, "B+"), (75, "B"), 
                  (70, "B-"), (65, "C+"), (60, "C"), (55, "C-"), (50, "D"), (0, "F")]
        grade = "F"
        for min_score, g in grades:
            if total_score >= min_score:
                grade = g
                break

        # Log audit
        log_audit('QUICK_ANALYSIS', {
            'url': validated_url,
            'score': total_score,
            'grade': grade
        }, user_id=session.get('pentester_id'), ip=get_client_ip())

        return jsonify({
            "success": True, 
            "data": {
                "url": validated_url, 
                "title": title, 
                "load_time": load_time,
                "size_kb": size_kb, 
                "status": response.status_code,
                "perf_score": round(perf_score, 1), 
                "security_score": round(security_score, 1),
                "total_score": round(total_score, 1), 
                "grade": grade, 
                "security": security,
                "headers": {k: v for k, v in headers.items() if k not in ['Set-Cookie']}
            }
        })

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({"success": False, "error": "An error occurred during analysis"}), 500

@app.route("/api/start-audit", methods=["POST"])
@limiter.limit("10 per hour")
@require_pentester
def start_audit():
    """Start full security audit."""
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"success": False, "error": "URL is required"}), 400

        url = data["url"].strip()

        # Validate URL
        if not url.startswith(("http://", "https://")):
            return jsonify({"success": False, "error": "Invalid URL format"}), 400

        validated_url = validate_url(url)
        if not validated_url:
            return jsonify({"success": False, "error": "Invalid URL"}), 400

        # Check for SSRF
        if is_blocked_url(validated_url):
            log_audit('SSRF_BLOCKED', {'url': validated_url}, 
                     user_id=session.get('pentester_id'), ip=get_client_ip())
            return jsonify({"success": False, "error": "URL blocked"}), 403

        audit_id = generate_secure_token(16)

        # Start scan in background
        def run_scan():
            try:
                scanner = SecurityScanner(validated_url, audit_id)
                findings = scanner.run_all_checks()

                # Subdomain scan
                domain = urlparse(validated_url).netloc
                subdomain_scanner = SubdomainScanner(domain)
                subdomains = subdomain_scanner.enumerate()

                # Compliance checks
                headers = dict(requests.get(validated_url, timeout=10).headers)
                ssl_info = {'version': 'TLS 1.2'}
                compliance = ComplianceChecker().check_all(findings, headers, ssl_info)

                # Calculate scores
                severity_weights = {'critical': 10, 'high': 5, 'medium': 3, 'low': 1, 'info': 0}
                total_weight = sum(severity_weights.get(f['severity'], 0) for f in findings)
                security_score = max(0, 100 - total_weight * 2)

                critical_count = sum(1 for f in findings if f['severity'] == 'critical')
                high_count = sum(1 for f in findings if f['severity'] == 'high')
                medium_count = sum(1 for f in findings if f['severity'] == 'medium')
                low_count = sum(1 for f in findings if f['severity'] == 'low')
                info_count = sum(1 for f in findings if f['severity'] == 'info')

                # Grade
                if security_score >= 90: grade = 'A'
                elif security_score >= 80: grade = 'B'
                elif security_score >= 70: grade = 'C'
                elif security_score >= 60: grade = 'D'
                else: grade = 'F'

                audit_data = {
                    'audit_id': audit_id,
                    'target_url': validated_url,
                    'target_domain': domain,
                    'findings': findings,
                    'subdomains': subdomains,
                    'compliance': compliance,
                    'total_findings': len(findings),
                    'critical_count': critical_count,
                    'high_count': high_count,
                    'medium_count': medium_count,
                    'low_count': low_count,
                    'info_count': info_count,
                    'security_score': round(security_score, 2),
                    'grade': grade,
                    'scan_date': datetime.datetime.now().isoformat()
                }

                # Generate PDF
                pdf_gen = PDFReportGenerator(audit_data)
                pdf_path = pdf_gen.generate()
                audit_data['report_path'] = pdf_path

                # Save to database
                user_id = session.get('pentester_id')
                db_manager.save_audit_result(user_id, {
                    'audit_id': audit_id,
                    'target_url': validated_url,
                    'target_domain': domain,
                    'scan_type': 'full',
                    'total_findings': len(findings),
                    'critical_count': critical_count,
                    'high_count': high_count,
                    'medium_count': medium_count,
                    'low_count': low_count,
                    'info_count': info_count,
                    'compliance_score': round(sum(c['score'] for c in compliance.values() if isinstance(c, dict) and 'score' in c) / len([c for c in compliance.values() if isinstance(c, dict) and 'score' in c]), 2),
                    'security_score': round(security_score, 2),
                    'grade': grade,
                    'status': 'completed',
                    'report_path': pdf_path,
                    'ip_address': get_client_ip(),
                    'user_agent': request.headers.get('User-Agent', '')
                })

                # Send email notification
                email = session.get('pentester_email')
                if email:
                    notifier = EmailNotifier()
                    notifier.send_audit_complete_email(email, audit_data, pdf_path)

                # Emit completion via SocketIO
                socketio.emit('audit_complete', {
                    'audit_id': audit_id,
                    'status': 'completed',
                    'findings_count': len(findings)
                }, room=audit_id)

            except Exception as e:
                logger.error(f"Audit scan error: {e}")
                socketio.emit('audit_error', {
                    'audit_id': audit_id,
                    'error': str(e)
                }, room=audit_id)

        threading.Thread(target=run_scan, daemon=True).start()

        log_audit('AUDIT_STARTED', {'url': validated_url, 'audit_id': audit_id}, 
                 user_id=session.get('pentester_id'), ip=get_client_ip())

        return jsonify({
            "success": True, 
            "audit_id": audit_id,
            "message": "Audit started successfully"
        })

    except Exception as e:
        logger.error(f"Start audit error: {e}")
        return jsonify({"success": False, "error": "Failed to start audit"}), 500

@app.route("/api/scan-phase", methods=["POST"])
@limiter.limit("20 per minute")
@require_pentester
def scan_phase():
    """Run specific scan phase."""
    try:
        data = request.get_json()
        if not data or "url" not in data or "phase" not in data:
            return jsonify({"success": False, "error": "URL and phase are required"}), 400

        url = data["url"].strip()
        phase = data["phase"]

        if not url.startswith(("http://", "https://")):
            return jsonify({"success": False, "error": "Invalid URL"}), 400

        validated_url = validate_url(url)
        if not validated_url:
            return jsonify({"success": False, "error": "Invalid URL"}), 400

        if is_blocked_url(validated_url):
            return jsonify({"success": False, "error": "URL blocked"}), 403

        audit_id = generate_secure_token(16)
        scanner = SecurityScanner(validated_url, audit_id)

        phase_methods = {
            'xss': scanner.check_xss,
            'sql_injection': scanner.check_sql_injection,
            'headers': scanner.check_security_headers,
            'ports': scanner.check_open_ports,
            'sensitive_files': scanner.check_sensitive_files,
            'ssl': scanner.check_ssl_tls,
            'csrf': scanner.check_csrf,
            'ssrf': scanner.check_ssrf,
            'idor': scanner.check_idor,
        }

        if phase not in phase_methods:
            return jsonify({"success": False, "error": "Invalid phase"}), 400

        phase_methods[phase]()

        return jsonify({
            "success": True,
            "audit_id": audit_id,
            "phase": phase,
            "findings": scanner.findings
        })

    except Exception as e:
        logger.error(f"Scan phase error: {e}")
        return jsonify({"success": False, "error": "Phase scan failed"}), 500

@app.route("/api/subdomain-scan", methods=["POST"])
@limiter.limit("10 per hour")
@require_pentester
def subdomain_scan():
    """Scan subdomains."""
    try:
        data = request.get_json()
        if not data or "domain" not in data:
            return jsonify({"success": False, "error": "Domain is required"}), 400

        domain = sanitize_input(data["domain"], 255)

        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$', domain):
            return jsonify({"success": False, "error": "Invalid domain format"}), 400

        try:
            ip = socket.getaddrinfo(domain, None)[0][4][0]
            if is_private_ip(ip):
                return jsonify({"success": False, "error": "Private domains are not allowed"}), 403
        except socket.gaierror:
            pass

        scanner = SubdomainScanner(domain)
        subdomains = scanner.enumerate()

        log_audit('SUBDOMAIN_SCAN', {'domain': domain, 'found': len(subdomains)}, 
                 user_id=session.get('pentester_id'), ip=get_client_ip())

        return jsonify({
            "success": True,
            "domain": domain,
            "subdomains_found": len(subdomains),
            "subdomains": subdomains
        })

    except Exception as e:
        logger.error(f"Subdomain scan error: {e}")
        return jsonify({"success": False, "error": "Subdomain scan failed"}), 500

@app.route("/api/generate-report", methods=["POST"])
@require_pentester
def generate_report():
    """Generate audit report."""
    try:
        data = request.get_json()
        if not data or "audit_id" not in data:
            return jsonify({"success": False, "error": "Audit ID is required"}), 400

        audit_id = sanitize_input(data["audit_id"], 64)

        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_history WHERE audit_id = ? AND user_id = ?",
                      (audit_id, session.get('pentester_id')))
        audit = cursor.fetchone()

        if not audit:
            return jsonify({"success": False, "error": "Audit not found"}), 404

        audit_dict = dict(audit)

        audit_data = {
            'audit_id': audit_dict['audit_id'],
            'target_url': audit_dict['target_url'],
            'scan_date': audit_dict['started_at'],
            'total_findings': audit_dict['total_findings'],
            'critical_count': audit_dict['critical_count'],
            'high_count': audit_dict['high_count'],
            'medium_count': audit_dict['medium_count'],
            'low_count': audit_dict['low_count'],
            'security_score': audit_dict['security_score'],
            'grade': audit_dict['grade']
        }

        pdf_gen = PDFReportGenerator(audit_data)
        pdf_path = pdf_gen.generate()

        return jsonify({
            "success": True,
            "report_path": pdf_path,
            "download_url": f"/api/download-report/{os.path.basename(pdf_path)}"
        })

    except Exception as e:
        logger.error(f"Generate report error: {e}")
        return jsonify({"success": False, "error": "Report generation failed"}), 500

@app.route("/api/download-report/<filename>")
@require_auth
def download_report(filename):
    """Download audit report."""
    try:
        filename = secure_filename(filename)

        if not filename or '..' in filename or filename.startswith('/'):
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400

        filepath = os.path.join(Config.UPLOAD_FOLDER, filename)

        real_path = os.path.realpath(filepath)
        allowed_dir = os.path.realpath(Config.UPLOAD_FOLDER)
        if not real_path.startswith(allowed_dir):
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'File not found'}), 404

        if not allowed_file(filename):
            return jsonify({'success': False, 'error': 'File type not allowed'}), 400

        log_audit('REPORT_DOWNLOAD', {'filename': filename}, 
                 user_id=session.get('pentester_id'), ip=get_client_ip())

        return send_from_directory(
            Config.UPLOAD_FOLDER, 
            filename, 
            as_attachment=True,
            mimetype='application/pdf'
        )

    except Exception as e:
        logger.error(f"Download report error: {e}")
        return jsonify({'success': False, 'error': 'Download failed'}), 500

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    """Register new user."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip().lower()

        if not all([username, password, email]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        if len(username) < 3 or len(username) > 50:
            return jsonify({'success': False, 'error': 'Username must be 3-50 characters'}), 400

        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return jsonify({'success': False, 'error': 'Username can only contain letters, numbers, and underscores'}), 400

        if not validate_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400

        is_valid, msg, strength = validate_password_strength(password)
        if not is_valid:
            return jsonify({'success': False, 'error': msg, 'password_strength': strength}), 400

        user_id, message = db_manager.create_user(username, password, email)

        if user_id:
            log_audit('USER_REGISTERED', {'username': username, 'email': email}, 
                     user_id=user_id, ip=get_client_ip())
            return jsonify({
                'success': True, 
                'message': 'Registration successful',
                'password_strength': strength
            })
        else:
            return jsonify({'success': False, 'error': message}), 409

    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'error': 'Registration failed'}), 500

@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    """User login."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body required'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not all([username, password]):
            return jsonify({'success': False, 'error': 'Username and password are required'}), 400

        user, message = db_manager.verify_user(username, password, get_client_ip())

        if user:
            session.permanent = True
            session['pentester_id'] = user['id']
            session['pentester_username'] = user['username']
            session['pentester_role'] = user['role']
            session['pentester_email'] = user['email']

            access_token = generate_jwt_token(user['id'], user['username'], user['role'])
            refresh_token = generate_jwt_token(user['id'], user['username'], user['role'], 'refresh')

            return jsonify({
                'success': True,
                'message': message,
                'role': user['role'],
                'username': user['username'],
                'access_token': access_token,
                'refresh_token': refresh_token,
                'api_key': user['api_key']
            })
        else:
            return jsonify({'success': False, 'error': message}), 401

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route("/api/refresh-token", methods=["POST"])
def refresh_token():
    """Refresh JWT access token."""
    try:
        data = request.get_json()
        if not data or 'refresh_token' not in data:
            return jsonify({'success': False, 'error': 'Refresh token required'}), 400

        payload = verify_jwt_token(data['refresh_token'], 'refresh')
        if not payload:
            return jsonify({'success': False, 'error': 'Invalid refresh token'}), 401

        new_access_token = generate_jwt_token(
            payload['user_id'], 
            payload['username'], 
            payload['role']
        )

        return jsonify({
            'success': True,
            'access_token': new_access_token
        })

    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'success': False, 'error': 'Token refresh failed'}), 500

@app.route("/api/profile")
@require_auth
def get_profile():
    """Get user profile."""
    try:
        user_id = g.user.get('user_id') or session.get('pentester_id')
        history = db_manager.get_user_audit_history(user_id, limit=10)

        return jsonify({
            'success': True,
            'profile': {
                'username': g.user.get('username') or session.get('pentester_username'),
                'role': g.user.get('role') or session.get('pentester_role'),
                'recent_audits': history
            }
        })

    except Exception as e:
        logger.error(f"Profile error: {e}")
        return jsonify({'success': False, 'error': 'Failed to get profile'}), 500

@app.route("/api/logout")
def logout():
    """Logout user."""
    try:
        user_id = session.get('pentester_id')
        log_audit('LOGOUT', {}, user_id=user_id, ip=get_client_ip())

        session.clear()
        return jsonify({'success': True, 'message': 'Logged out successfully'})

    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'success': False, 'error': 'Logout failed'}), 500

@app.route("/api/admin/users")
@require_admin
def list_users():
    """List all users (admin only)."""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, role, is_active, last_login, created_at FROM users ORDER BY created_at DESC")
        users = [dict(row) for row in cursor.fetchall()]

        return jsonify({'success': True, 'users': users})

    except Exception as e:
        logger.error(f"List users error: {e}")
        return jsonify({'success': False, 'error': 'Failed to list users'}), 500

@app.route("/api/active-audits")
@require_pentester
def active_audits():
    """Get active audits."""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_history WHERE status = 'running' AND user_id = ? ORDER BY started_at DESC",
                      (session.get('pentester_id'),))
        audits = [dict(row) for row in cursor.fetchall()]

        return jsonify({'success': True, 'audits': audits})

    except Exception as e:
        logger.error(f"Active audits error: {e}")
        return jsonify({'success': False, 'error': 'Failed to get active audits'}), 500

@app.route("/api/audit-history")
@require_auth
def audit_history():
    """Get user audit history."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        if page < 1:
            page = 1
        if per_page < 1 or per_page > 100:
            per_page = 20

        offset = (page - 1) * per_page
        user_id = g.user.get('user_id') or session.get('pentester_id')

        history = db_manager.get_user_audit_history(user_id, limit=per_page, offset=offset)

        return jsonify({
            'success': True,
            'audits': history,
            'page': page,
            'per_page': per_page
        })

    except Exception as e:
        logger.error(f"Audit history error: {e}")
        return jsonify({'success': False, 'error': 'Failed to get audit history'}), 500

# =========================
# SOCKET.IO EVENTS
# =========================
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'status': 'connected', 'sid': request.sid})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe_audit')
def handle_subscribe(data):
    """Subscribe to audit updates."""
    audit_id = data.get('audit_id')
    if audit_id:
        join_room(audit_id)
        emit('subscribed', {'audit_id': audit_id, 'status': 'subscribed'})

@socketio.on('unsubscribe_audit')
def handle_unsubscribe(data):
    """Unsubscribe from audit updates."""
    audit_id = data.get('audit_id')
    if audit_id:
        leave_room(audit_id)
        emit('unsubscribed', {'audit_id': audit_id, 'status': 'unsubscribed'})

# =========================
# ERROR HANDLERS
# =========================
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'success': False, 'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.errorhandler(429)
def rate_limit_handler(error):
    """Handle rate limit errors."""
    return jsonify({
        'success': False, 
        'error': 'Rate limit exceeded. Please try again later.',
        'retry_after': str(error.description) if hasattr(error, 'description') else 'unknown'
    }), 429

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    return jsonify({'success': False, 'error': 'Access forbidden'}), 403

@app.errorhandler(400)
def bad_request(error):
    """Handle 400 errors."""
    return jsonify({'success': False, 'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 errors."""
    return jsonify({'success': False, 'error': 'Authentication required'}), 401

# =========================
# MAIN
# =========================
if __name__ == '__main__':
    print("=" * 60)
    print("Web Security Analyzer v3.0 - Professional Pentest Platform")
    print(f"Python: {sys.version}")
    print("=" * 60)

    # Optionally create default admin if explicitly allowed via environment
    if os.environ.get('CREATE_DEFAULT_ADMIN', 'False').lower() == 'true':
        admin_password = os.environ.get('DEFAULT_ADMIN_PASSWORD')
        if admin_password:
            try:
                db_manager.create_user('admin', admin_password, 'admin@websecurity.app', 'admin')
                print("✅ Default admin user created from DEFAULT_ADMIN_PASSWORD environment value.")
            except Exception:
                print("ℹ️ Default admin user already exists or creation failed.")
        else:
            print("⚠️ CREATE_DEFAULT_ADMIN is true but DEFAULT_ADMIN_PASSWORD is not set; skipping creation. Use setup script to create admin.")

    # Run application
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true',
        use_reloader=False
    )
