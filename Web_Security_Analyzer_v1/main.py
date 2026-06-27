# main.py - Python 3.8 Compatible (Fixed Warnings)
import sys
import warnings

# Cryptography ogohlantirishini o'chirish
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="OpenSSL")

print("=" * 60)
print("Professional Pentest Platform v2.0")
print(f"Python: {sys.version}")
print("=" * 60)

from flask import Flask, render_template, request, jsonify, session, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
import requests
import time
import socket
import hashlib
import datetime
import re
import logging
import secrets
import sqlite3
import threading
import smtplib
import os
import json
import concurrent.futures
import dns.resolver
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# OpenSSL import - ogohlantirishlarni bostirish bilan
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
    print("⚠ OpenSSL not available - SSL certificate analysis disabled")

# whois import - xatoliklarni boshqarish bilan
WHOIS_AVAILABLE = False
try:
    import whois
    WHOIS_AVAILABLE = True
    print("✓ whois library loaded")
except (ImportError, TypeError, AttributeError) as e:
    print(f"⚠ whois library not available: {e}")
    # Fallback whois class
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

# PDF Generator
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# =========================
# APP INITIALIZATION
# =========================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
app.config['WTF_CSRF_ENABLED'] = True
app.config['UPLOAD_FOLDER'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Reports papkasini yaratish
os.makedirs('reports', exist_ok=True)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting - Redis yoki fayl ombori bilan (xotira emas)
try:
    import redis
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["500 per day", "100 per hour"],
        storage_uri="memory://"  # Redis bo'lmasa memory ishlatiladi
    )
except ImportError:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["500 per day", "100 per hour"]
    )

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pentest.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# =========================
# USER MANAGEMENT SYSTEM
# =========================
class UserManager:
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                api_key TEXT UNIQUE,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target_url TEXT,
                audit_id TEXT,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                subdomains_found INTEGER DEFAULT 0,
                compliance_score REAL DEFAULT 0,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE,
                indicator_type TEXT,
                threat_data TEXT,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
        self.create_default_admin()
    
    def create_default_admin(self):
        try:
            from werkzeug.security import generate_password_hash
            conn = sqlite3.connect(self.db_path)
            existing = conn.execute(
                'SELECT id FROM users WHERE username = ?', ('admin',)
            ).fetchone()
            
            if not existing:
                password_hash = generate_password_hash('admin123')
                api_key = secrets.token_urlsafe(32)
                conn.execute(
                    'INSERT INTO users (username, password_hash, email, role, api_key) VALUES (?, ?, ?, ?, ?)',
                    ('admin', password_hash, 'admin@pentest.local', 'admin', api_key)
                )
                conn.commit()
                logger.info("Default admin user created")
            
            conn.close()
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
    
    def create_user(self, username, password, email, role='user'):
        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash(password)
        api_key = secrets.token_urlsafe(32)
        
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash, email, role, api_key) VALUES (?, ?, ?, ?, ?)',
                (username, password_hash, email, role, api_key)
            )
            conn.commit()
            user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
            logger.info(f"User created: {username}")
            return user_id
        except sqlite3.IntegrityError:
            logger.warning(f"Username already exists: {username}")
            return None
        finally:
            conn.close()
    
    def verify_user(self, username, password):
        from werkzeug.security import check_password_hash
        conn = sqlite3.connect(self.db_path)
        user = conn.execute(
            'SELECT id, username, password_hash, email, role, api_key FROM users WHERE username = ? AND is_active = 1',
            (username,)
        ).fetchone()
        
        if user and check_password_hash(user[2], password):
            conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            conn.commit()
            conn.close()
            return {
                'id': user[0], 'username': user[1],
                'email': user[3], 'role': user[4], 'api_key': user[5]
            }
        conn.close()
        return None
    
    def get_user_by_api_key(self, api_key):
        conn = sqlite3.connect(self.db_path)
        user = conn.execute(
            'SELECT id, username, role FROM users WHERE api_key = ? AND is_active = 1',
            (api_key,)
        ).fetchone()
        conn.close()
        return {'id': user[0], 'username': user[1], 'role': user[2]} if user else None
    
    def save_audit_result(self, user_id, target_url, audit_id, total_findings, critical_count, high_count, subdomains_found=0, compliance_score=0, status='completed'):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            'INSERT INTO audit_history (user_id, target_url, audit_id, total_findings, critical_count, high_count, subdomains_found, compliance_score, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (user_id, target_url, audit_id, total_findings, critical_count, high_count, subdomains_found, compliance_score, status)
        )
        conn.commit()
        conn.close()
    
    def get_user_audit_history(self, user_id, limit=20):
        conn = sqlite3.connect(self.db_path)
        history = conn.execute(
            'SELECT target_url, audit_id, total_findings, critical_count, high_count, subdomains_found, compliance_score, status, created_at FROM audit_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()
        conn.close()
        return [
            {
                'target_url': row[0], 'audit_id': row[1],
                'total_findings': row[2], 'critical_count': row[3],
                'high_count': row[4], 'subdomains_found': row[5],
                'compliance_score': row[6], 'status': row[7], 'created_at': row[8]
            }
            for row in history
        ]
    
    def cache_threat_intel(self, indicator, indicator_type, threat_data):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            'INSERT OR REPLACE INTO threat_intel_cache (indicator, indicator_type, threat_data, last_checked) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
            (indicator, indicator_type, json.dumps(threat_data))
        )
        conn.commit()
        conn.close()
    
    def get_cached_threat(self, indicator):
        conn = sqlite3.connect(self.db_path)
        result = conn.execute(
            'SELECT threat_data FROM threat_intel_cache WHERE indicator = ? AND last_checked > datetime("now", "-24 hours")',
            (indicator,)
        ).fetchone()
        conn.close()
        return json.loads(result[0]) if result else None

# Global instances
user_manager = UserManager()

# =========================
# LIVE AUDIT MONITOR
# =========================
class LiveAuditMonitor:
    def __init__(self):
        self.active_audits = {}
    
    def start_audit(self, audit_id, target_url, user_id):
        self.active_audits[audit_id] = {
            'status': 'running', 'target': target_url,
            'user_id': user_id, 'start_time': datetime.datetime.now(),
            'phases_completed': 0, 'total_phases': 12, 'findings': []
        }
        socketio.emit('audit_started', {
            'audit_id': audit_id, 'target': target_url,
            'timestamp': datetime.datetime.now().isoformat()
        }, room=f'audit_{audit_id}')
    
    def update_phase(self, audit_id, phase_name, phase_num, total_phases, findings_count=0):
        if audit_id in self.active_audits:
            progress = round((phase_num / total_phases) * 100)
            self.active_audits[audit_id]['phases_completed'] = phase_num
            socketio.emit('phase_update', {
                'audit_id': audit_id, 'phase': phase_name,
                'phase_num': phase_num, 'total_phases': total_phases,
                'progress': progress, 'findings_count': findings_count
            }, room=f'audit_{audit_id}')
    
    def add_finding(self, audit_id, finding):
        if audit_id in self.active_audits:
            self.active_audits[audit_id]['findings'].append(finding)
            socketio.emit('new_finding', {'audit_id': audit_id, 'finding': finding}, room=f'audit_{audit_id}')
    
    def complete_audit(self, audit_id, report):
        if audit_id in self.active_audits:
            self.active_audits[audit_id]['status'] = 'completed'
            socketio.emit('audit_completed', {'audit_id': audit_id, 'report': report}, room=f'audit_{audit_id}')
    
    def get_active_audits_count(self):
        return len([a for a in self.active_audits.values() if a['status'] == 'running'])

live_monitor = LiveAuditMonitor()

# =========================
# SUBDOMAIN SCANNER
# =========================
class SubdomainScanner:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.whois_info = None
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
            'ns1', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'api', 'dev', 'staging', 'app', 'admin', 'secure', 'vpn',
            'portal', 'cdn', 'media', 'static', 'files', 'docs',
            'support', 'blog', 'shop', 'test', 'status', 'monitor',
            'dashboard', 'remote', 'gateway', 'proxy', 'db', 'mysql'
        ]
    
    def check_subdomain(self, subdomain):
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            if answers:
                return {'domain': full_domain, 'ips': [str(r) for r in answers]}
        except:
            pass
        return None
    
    def enumerate(self, audit_id=None):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in self.common_subdomains}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result['domain'])
                    results.append(result)
                    if audit_id:
                        live_monitor.add_finding(audit_id, {
                            'type': 'Subdomain Discovered', 'severity': 'INFO',
                            'subdomain': result['domain'], 'ips': result['ips'],
                            'description': f'Active subdomain: {result["domain"]}'
                        })
        return results
    
    def get_whois_info(self):
        try:
            w = whois.whois(self.domain)
            self.whois_info = {
                'registrar': str(w.registrar) if w.registrar else 'Unknown',
                'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
                'name_servers': list(w.name_servers) if w.name_servers else [],
                'status': str(w.status) if w.status else 'Unknown'
            }
        except Exception as e:
            logger.error(f"WHOIS failed: {e}")
            self.whois_info = {'error': str(e)}
        return self.whois_info

# =========================
# COMPLIANCE CHECKER
# =========================
class ComplianceChecker:
    def __init__(self):
        self.standards = {
            'PCI_DSS': self.check_pci_dss,
            'HIPAA': self.check_hipaa,
            'GDPR': self.check_gdpr,
            'SOC2': self.check_soc2,
            'ISO27001': self.check_iso27001
        }
    
    def check_all(self, findings, headers, ssl_info):
        results = {}
        for standard, check_func in self.standards.items():
            try:
                results[standard] = check_func(findings, headers, ssl_info)
            except Exception as e:
                results[standard] = {'error': str(e)}
        return results
    
    def check_pci_dss(self, findings, headers, ssl_info):
        requirements = {
            'firewall': {'status': 'pass', 'requirement': '1.1'},
            'encryption': {'status': 'pass', 'requirement': '3.4'},
            'access_control': {'status': 'pass', 'requirement': '7.1'},
            'monitoring': {'status': 'pass', 'requirement': '10.1'},
            'testing': {'status': 'pass', 'requirement': '11.1'},
            'vulnerability_management': {'status': 'pass', 'requirement': '6.1'}
        }
        
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            if 'open port' in finding_type:
                requirements['firewall']['status'] = 'fail'
            if 'https' in finding_type and 'not enabled' in finding.get('description', '').lower():
                requirements['encryption']['status'] = 'fail'
            if any(x in finding_type for x in ['xss', 'sql injection']):
                requirements['vulnerability_management']['status'] = 'fail'
            if 'missing security header' in finding_type:
                requirements['access_control']['status'] = 'fail'
        
        passed = sum(1 for r in requirements.values() if r['status'] == 'pass')
        score = round((passed / len(requirements)) * 100, 2)
        
        return {
            'standard': 'PCI DSS 4.0', 'score': score,
            'status': 'COMPLIANT' if score >= 80 else 'NON-COMPLIANT',
            'requirements': requirements
        }
    
    def check_hipaa(self, findings, headers, ssl_info):
        requirements = {
            'encryption': {'status': 'pass'},
            'access_control': {'status': 'pass'},
            'audit_controls': {'status': 'pass'},
            'integrity': {'status': 'pass'},
            'authentication': {'status': 'pass'}
        }
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            if 'https' in finding_type and 'not enabled' in finding.get('description', '').lower():
                requirements['encryption']['status'] = 'fail'
            if 'security header' in finding_type:
                requirements['access_control']['status'] = 'fail'
        
        passed = sum(1 for r in requirements.values() if r['status'] == 'pass')
        score = round((passed / len(requirements)) * 100, 2)
        return {
            'standard': 'HIPAA', 'score': score,
            'status': 'COMPLIANT' if score >= 80 else 'NON-COMPLIANT',
            'requirements': requirements
        }
    
    def check_gdpr(self, findings, headers, ssl_info):
        requirements = {
            'data_protection': {'status': 'pass'},
            'encryption': {'status': 'pass'},
            'breach_notification': {'status': 'pass'},
            'consent_management': {'status': 'pass'}
        }
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            if 'https' in finding_type and 'not enabled' in finding.get('description', '').lower():
                requirements['encryption']['status'] = 'fail'
            if 'sensitive file' in finding_type:
                requirements['data_protection']['status'] = 'fail'
        
        passed = sum(1 for r in requirements.values() if r['status'] == 'pass')
        score = round((passed / len(requirements)) * 100, 2)
        return {
            'standard': 'GDPR', 'score': score,
            'status': 'COMPLIANT' if score >= 80 else 'NON-COMPLIANT',
            'requirements': requirements
        }
    
    def check_soc2(self, findings, headers, ssl_info):
        requirements = {
            'security': {'status': 'pass'},
            'availability': {'status': 'pass'},
            'confidentiality': {'status': 'pass'},
            'privacy': {'status': 'pass'}
        }
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            if 'https' in finding_type and 'not enabled' in finding.get('description', '').lower():
                requirements['security']['status'] = 'fail'
        
        passed = sum(1 for r in requirements.values() if r['status'] == 'pass')
        score = round((passed / len(requirements)) * 100, 2)
        return {
            'standard': 'SOC 2', 'score': score,
            'status': 'COMPLIANT' if score >= 80 else 'NON-COMPLIANT',
            'requirements': requirements
        }
    
    def check_iso27001(self, findings, headers, ssl_info):
        requirements = {
            'information_security': {'status': 'pass'},
            'asset_management': {'status': 'pass'},
            'access_control': {'status': 'pass'},
            'cryptography': {'status': 'pass'}
        }
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            if 'https' in finding_type and 'not enabled' in finding.get('description', '').lower():
                requirements['cryptography']['status'] = 'fail'
            if 'missing security header' in finding_type:
                requirements['access_control']['status'] = 'fail'
        
        passed = sum(1 for r in requirements.values() if r['status'] == 'pass')
        score = round((passed / len(requirements)) * 100, 2)
        return {
            'standard': 'ISO 27001', 'score': score,
            'status': 'COMPLIANT' if score >= 80 else 'NON-COMPLIANT',
            'requirements': requirements
        }

# =========================
# THREAT INTELLIGENCE
# =========================
class ThreatIntelligence:
    def __init__(self):
        self.alienvault_url = 'https://otx.alienvault.com/api/v1/indicators/'
    
    def check_ip_reputation(self, ip_address):
        threats = []
        cached = user_manager.get_cached_threat(ip_address)
        if cached:
            return cached
        
        try:
            response = requests.get(
                f"{self.alienvault_url}IPv4/{ip_address}/general",
                headers={'X-OTX-API-KEY': os.environ.get('OTX_KEY', '')},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('pulse_info', {}).get('count', 0)
                if pulses > 0:
                    threats.append({
                        'source': 'AlienVault OTX', 'type': 'malicious_ip',
                        'threat_level': 'HIGH' if pulses > 10 else 'MEDIUM',
                        'pulses': pulses,
                        'description': f'Reported in {pulses} threat pulses'
                    })
        except Exception as e:
            logger.error(f"AlienVault check failed: {e}")
        
        user_manager.cache_threat_intel(ip_address, 'ip', threats)
        return threats
    
    def get_domain_reputation(self, domain):
        threats = []
        cached = user_manager.get_cached_threat(domain)
        if cached:
            return cached
        
        try:
            response = requests.get(
                f"{self.alienvault_url}domain/{domain}/general",
                headers={'X-OTX-API-KEY': os.environ.get('OTX_KEY', '')},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('pulse_info', {}).get('count', 0)
                if pulses > 0:
                    threats.append({
                        'source': 'AlienVault OTX', 'type': 'malicious_domain',
                        'threat_level': 'HIGH' if pulses > 10 else 'MEDIUM',
                        'pulses': pulses,
                        'description': f'Reported in {pulses} threat pulses'
                    })
        except Exception as e:
            logger.error(f"Domain reputation check failed: {e}")
        
        user_manager.cache_threat_intel(domain, 'domain', threats)
        return threats
    
    def get_ssl_info(self, hostname, port=443):
        if OpenSSL is None:
            return {'error': 'OpenSSL library not available'}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    return {
                        'issuer': str(dict(x509.get_issuer().get_components())),
                        'subject': str(dict(x509.get_subject().get_components())),
                        'version': x509.get_version(),
                        'serial_number': x509.get_serial_number(),
                        'not_before': x509.get_notBefore().decode() if x509.get_notBefore() else 'N/A',
                        'not_after': x509.get_notAfter().decode() if x509.get_notAfter() else 'N/A',
                        'has_expired': x509.has_expired(),
                        'signature_algorithm': x509.get_signature_algorithm().decode() if x509.get_signature_algorithm() else 'N/A'
                    }
        except Exception as e:
            return {'error': str(e)}

# Global instances
threat_intel = ThreatIntelligence()
compliance_checker = ComplianceChecker()

# =========================
# PDF REPORT GENERATOR
# =========================
class PDFReportGenerator:
    def __init__(self, audit_data):
        self.audit_data = audit_data
        self.filename = f"security_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        self.filepath = os.path.join('reports', self.filename)
    
    def generate(self):
        doc = SimpleDocTemplate(self.filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#ff4757'))
        story.append(Paragraph("PROFESSIONAL SECURITY AUDIT REPORT", title_style))
        story.append(Spacer(1, 12))
        
        info_style = ParagraphStyle('InfoStyle', parent=styles['Normal'], fontSize=12, leading=18)
        story.append(Paragraph(f"<b>Target:</b> {self.audit_data.get('target', 'N/A')}", info_style))
        story.append(Paragraph(f"<b>Date:</b> {self.audit_data.get('timestamp', 'N/A')}", info_style))
        story.append(Paragraph(f"<b>Total Findings:</b> {self.audit_data.get('total_findings', 0)}", info_style))
        story.append(Spacer(1, 12))
        
        # Findings
        story.append(Paragraph("DETAILED FINDINGS", styles['Heading2']))
        findings = self.audit_data.get('findings', [])
        for i, finding in enumerate(findings[:20], 1):
            story.append(Paragraph(f"<b>#{i} [{finding.get('severity', '?')}] {finding.get('type', 'Unknown')}</b>", info_style))
            story.append(Paragraph(f"{finding.get('description', 'N/A')}", info_style))
            if finding.get('fix'):
                story.append(Paragraph(f"<b>Fix:</b> {finding['fix']}", info_style))
            story.append(Spacer(1, 8))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph("Generated by Professional Pentest Platform v2.0", ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)))
        
        doc.build(story)
        return self.filepath

# =========================
# EMAIL NOTIFIER
# =========================
class EmailNotifier:
    def __init__(self):
        self.smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT', 587))
        self.username = os.environ.get('SMTP_USERNAME', '')
        self.password = os.environ.get('SMTP_PASSWORD', '')
    
    def send_audit_complete_email(self, to_email, audit_data, pdf_file=None):
        if not self.username or not self.password:
            return False
        
        def send():
            try:
                msg = MIMEMultipart()
                msg['Subject'] = f"Security Audit Complete - {audit_data.get('target', 'Unknown')}"
                msg['From'] = self.username
                msg['To'] = to_email
                
                overall_risk = audit_data.get('overall_risk', 'UNKNOWN')
                risk_color = '#ff4757' if overall_risk in ['CRITICAL', 'HIGH'] else '#ffa502'
                
                html = f"""
                <html><body style="font-family: Arial; background: #0a0a1a; color: white; padding: 20px;">
                    <div style="max-width: 600px; margin: 0 auto; background: #1e1e2f; padding: 30px; border-radius: 15px;">
                        <h2 style="color: #ff4757;">Security Audit Complete</h2>
                        <p><strong>Target:</strong> {audit_data.get('target', 'N/A')}</p>
                        <p><strong>Risk:</strong> <span style="color: {risk_color};">{overall_risk}</span></p>
                        <p><strong>Total Findings:</strong> {audit_data.get('total_findings', 0)}</p>
                        <p>Full report attached.</p>
                    </div>
                </body></html>
                """
                msg.attach(MIMEText(html, 'html'))
                
                if pdf_file and os.path.exists(pdf_file):
                    with open(pdf_file, 'rb') as f:
                        attachment = MIMEApplication(f.read(), _subtype='pdf')
                        attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(pdf_file))
                        msg.attach(attachment)
                
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.username, self.password)
                    server.send_message(msg)
                
                logger.info(f"Email sent to {to_email}")
            except Exception as e:
                logger.error(f"Email failed: {e}")
        
        thread = threading.Thread(target=send, daemon=True)
        thread.start()
        return True

email_notifier = EmailNotifier()

# =========================
# DECORATORS
# =========================
def require_pentester(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'pentester_id' not in session:
            return jsonify({'error': 'Professional access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('pentester_role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def require_audit_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'audit_token' not in session:
            return jsonify({'error': 'No active audit session'}), 401
        return f(*args, **kwargs)
    return decorated_function

# =========================
# SECURITY HEADERS
# =========================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# =========================
# HELPERS
# =========================
def generate_audit_token():
    return hashlib.sha256(
        f"{datetime.datetime.now()}{request.remote_addr}{secrets.token_hex(16)}".encode()
    ).hexdigest()

def is_authorized_audit(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        forbidden_domains = ['.gov', '.mil']
        if any(hostname.endswith(d) for d in forbidden_domains):
            return False
        blocked_ips = ['169.254.169.254', 'metadata.google.internal', '127.0.0.1', 'localhost']
        if hostname in blocked_ips:
            return False
        if 'audit_token' not in session:
            return False
        return True
    except:
        return False

# =========================
# SECURITY SCANNER
# =========================
class SecurityScanner:
    def __init__(self, target_url, audit_id):
        self.target = target_url
        self.audit_id = audit_id
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecurityAudit/2.0'})
    
    def check_xss(self):
        xss_payloads = ['<script>alert("XSS")</script>', '"><script>alert(1)</script>']
        for payload in xss_payloads:
            try:
                test_url = f"{self.target}?q={payload}"
                response = self.session.get(test_url, timeout=5)
                if payload in response.text:
                    self.findings.append({
                        'type': 'Cross-Site Scripting (XSS)', 'severity': 'HIGH',
                        'location': test_url, 'payload': payload,
                        'description': 'Reflected XSS detected',
                        'fix': 'Input validation va output encoding'
                    })
            except:
                continue
    
    def check_sql_injection(self):
        sql_payloads = [("' OR '1'='1", "Basic SQLi"), ("' OR 1=1--", "Comment SQLi")]
        sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite3::']
        for payload, sqli_type in sql_payloads:
            try:
                test_url = f"{self.target}?id={payload}"
                response = self.session.get(test_url, timeout=5)
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        self.findings.append({
                            'type': 'SQL Injection', 'severity': 'CRITICAL',
                            'sqli_type': sqli_type, 'location': test_url,
                            'description': f'SQL Injection ({sqli_type}) detected',
                            'fix': 'Parametrized queries yoki ORM'
                        })
            except:
                continue
    
    def check_security_headers(self):
        try:
            response = self.session.get(self.target, timeout=5)
            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS missing - MITM risk',
                'Content-Security-Policy': 'CSP missing - XSS risk',
                'X-Frame-Options': 'Clickjacking risk',
                'X-Content-Type-Options': 'MIME sniffing risk'
            }
            for header, desc in security_headers.items():
                if header not in headers:
                    self.findings.append({
                        'type': 'Missing Security Header', 'severity': 'MEDIUM',
                        'header': header, 'description': desc,
                        'fix': f'{header} header qo\'shing'
                    })
            return headers
        except:
            return {}
    
    def check_open_ports(self):
        common_ports = {21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 8080: 'Proxy'}
        hostname = urlparse(self.target).hostname
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((hostname, port)) == 0:
                    self.findings.append({
                        'type': 'Open Port', 'severity': 'LOW',
                        'port': port, 'service': service,
                        'description': f'Port {port} ({service}) open',
                        'fix': f'{port} portini yoping yoki firewall'
                    })
                sock.close()
            except:
                continue
    
    def check_sensitive_files(self):
        paths = ['/.git/', '/.env', '/admin/', '/wp-admin/', '/config.php']
        for path in paths:
            try:
                test_url = f"{self.target.rstrip('/')}{path}"
                response = self.session.get(test_url, timeout=5)
                if response.status_code != 404:
                    self.findings.append({
                        'type': 'Sensitive File', 'severity': 'HIGH',
                        'path': path, 'description': f'Accessible: {path}',
                        'fix': f'{path} ga kirishni bloklang'
                    })
            except:
                continue
    
    def check_ssl_tls(self):
        parsed = urlparse(self.target)
        if parsed.scheme == 'https':
            self.findings.append({'type': 'SSL/TLS Active', 'severity': 'INFO', 'description': 'HTTPS enabled'})
        else:
            self.findings.append({'type': 'No HTTPS', 'severity': 'HIGH', 'description': 'HTTPS not enabled', 'fix': 'SSL o\'rnating'})
    
    def generate_report(self):
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x['severity'], 99))
        stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            stats[f['severity']] = stats.get(f['severity'], 0) + 1
        
        risk = 'SECURE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if any(f['severity'] == s for f in self.findings):
                risk = s
                break
        
        return {
            'audit_id': self.audit_id, 'target': self.target,
            'timestamp': datetime.datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'severity_breakdown': stats,
            'findings': sorted_findings,
            'recommendations': [
                {'priority': f['severity'], 'issue': f['type'], 'fix': f.get('fix', 'N/A')}
                for f in sorted_findings if 'fix' in f
            ],
            'overall_risk': risk
        }

# =========================
# ROUTES
# =========================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/pentest-dashboard")
@require_pentester
def pentest_dashboard():
    return render_template("audit_dashboard.html")

@app.route("/analyze", methods=["POST"])
@limiter.limit("30 per minute")
def analyze():
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"success": False, "error": "URL required"}), 400
        
        url = data["url"]
        if not url.startswith(("http://", "https://")):
            return jsonify({"success": False, "error": "Invalid URL format"}), 400
        
        start = time.time()
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        load_time = round(time.time() - start, 2)
        size_kb = round(len(response.text) / 1024, 2)
        
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No title"
        headers = response.headers
        
        security = {
            "https": response.url.startswith("https"),
            "hsts": "Strict-Transport-Security" in headers,
            "csp": "Content-Security-Policy" in headers,
            "x_frame": "X-Frame-Options" in headers,
            "content_type": "Content-Type" in headers
        }
        
        security_score = sum(security.values()) * 20
        perf_score = 100
        if load_time > 3: perf_score -= 40
        elif load_time > 2: perf_score -= 20
        if size_kb > 2000: perf_score -= 20
        perf_score = max(perf_score, 0)
        
        total_score = (perf_score + security_score) // 2
        
        grades = [(90, "A"), (75, "B"), (60, "C"), (40, "D")]
        grade = "F"
        for min_score, g in grades:
            if total_score >= min_score:
                grade = g
                break
        
        return jsonify({"success": True, "data": {
            "url": url, "title": title, "load_time": load_time,
            "size_kb": size_kb, "status": response.status_code,
            "perf_score": perf_score, "security_score": security_score,
            "total_score": total_score, "grade": grade, "security": security
        }})
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "Request timeout"}), 408
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return jsonify({"success": False, "error": "Analysis failed"}), 500

@app.route("/start-audit", methods=["POST"])
@limiter.limit("10 per hour")
@require_pentester
def start_audit():
    try:
        data = request.get_json()
        target_url = data.get('url')
        owner_email = data.get('owner_email')
        
        if not target_url:
            return jsonify({'success': False, 'error': 'Target URL required'}), 400
        
        audit_token = generate_audit_token()
        session['audit_token'] = audit_token
        session['target_url'] = target_url
        session['owner_email'] = owner_email
        live_monitor.start_audit(audit_token, target_url, session.get('pentester_id'))
        
        logger.info(f"Audit started: {target_url}")
        return jsonify({'success': True, 'audit_id': audit_token, 'target': target_url})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/full-audit", methods=["POST"])
@limiter.limit("5 per hour")
@require_audit_token
def full_audit():
    try:
        target_url = request.get_json().get('url', session.get('target_url'))
        audit_id = session.get('audit_token')
        
        if not is_authorized_audit(target_url):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        scanner = SecurityScanner(target_url, audit_id)
        hostname = urlparse(target_url).hostname
        
        # Barcha tekshiruvlar
        live_monitor.update_phase(audit_id, 'Security Headers', 1, 8)
        headers = scanner.check_security_headers()
        
        live_monitor.update_phase(audit_id, 'SSL/TLS', 2, 8)
        scanner.check_ssl_tls()
        
        live_monitor.update_phase(audit_id, 'XSS Scan', 3, 8)
        scanner.check_xss()
        
        live_monitor.update_phase(audit_id, 'SQLi Scan', 4, 8)
        scanner.check_sql_injection()
        
        live_monitor.update_phase(audit_id, 'Port Scan', 5, 8)
        scanner.check_open_ports()
        
        live_monitor.update_phase(audit_id, 'Sensitive Files', 6, 8)
        scanner.check_sensitive_files()
        
        live_monitor.update_phase(audit_id, 'Subdomain + Intel', 7, 8)
        subdomains = SubdomainScanner(hostname).enumerate(audit_id)
        domain_threats = threat_intel.get_domain_reputation(hostname)
        ssl_info = threat_intel.get_ssl_info(hostname) if target_url.startswith('https') else None
        compliance = compliance_checker.check_all(scanner.findings, headers, ssl_info)
        
        live_monitor.update_phase(audit_id, 'Final Report', 8, 8)
        report = scanner.generate_report()
        report.update({
            'subdomain_count': len(subdomains),
            'subdomains': [s['domain'] for s in subdomains[:20]],
            'domain_threats': domain_threats,
            'ssl_info': ssl_info,
            'compliance': compliance
        })
        
        session['last_report'] = report
        
        # PDF va email
        pdf_file = PDFReportGenerator(report).generate()
        if session.get('owner_email'):
            email_notifier.send_audit_complete_email(session['owner_email'], report, pdf_file)
        
        live_monitor.complete_audit(audit_id, report)
        
        return jsonify({
            'success': True, 'report': report,
            'pdf_report': os.path.basename(pdf_file),
            'message': f'Audit complete. Found {report["total_findings"]} issues.'
        })
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/scan-phase", methods=["POST"])
@require_audit_token
def scan_phase():
    try:
        data = request.get_json()
        phase = data.get('phase')
        target_url = data.get('target', session.get('target_url'))
        
        scanner = SecurityScanner(target_url, session.get('audit_token'))
        phases = {
            'Security Headers Check': scanner.check_security_headers,
            'SSL/TLS Check': scanner.check_ssl_tls,
            'XSS Detection': scanner.check_xss,
            'SQL Injection Test': scanner.check_sql_injection,
            'Port Scanning': scanner.check_open_ports,
            'Sensitive Files': scanner.check_sensitive_files
        }
        
        if phase in phases:
            phases[phase]()
        
        return jsonify({'success': True, 'phase': phase, 'findings': scanner.findings})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/subdomain-scan", methods=["POST"])
@require_audit_token
def subdomain_scan():
    try:
        domain = request.get_json().get('domain') or urlparse(session.get('target_url')).hostname
        scanner = SubdomainScanner(domain)
        subdomains = scanner.enumerate()
        return jsonify({
            'success': True, 'domain': domain,
            'subdomains': [s['domain'] for s in subdomains],
            'total_found': len(subdomains)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/generate-report", methods=["POST"])
@require_audit_token
def generate_report():
    try:
        report = session.get('last_report')
        if not report:
            return jsonify({'success': False, 'error': 'No audit data'}), 404
        pdf_file = PDFReportGenerator(report).generate()
        return jsonify({'success': True, 'pdf_file': os.path.basename(pdf_file)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/download-report/<filename>")
@require_pentester
def download_report(filename):
    filepath = os.path.join('reports', filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype='application/pdf')
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.route("/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    try:
        data = request.get_json()
        username, password, email = data.get('username'), data.get('password'), data.get('email')
        if not all([username, password, email]):
            return jsonify({'success': False, 'error': 'All fields required'}), 400
        if len(password) < 8:
            return jsonify({'success': False, 'error': 'Password too short'}), 400
        
        user_id = user_manager.create_user(username, password, email)
        if user_id:
            return jsonify({'success': True, 'message': 'Registered successfully'})
        return jsonify({'success': False, 'error': 'Username exists'}), 409
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/pentest-login", methods=["POST"])
def pentest_login():
    try:
        data = request.get_json()
        user = user_manager.verify_user(data.get('username'), data.get('password'))
        if user:
            session['pentester_id'] = user['id']
            session['pentester_username'] = user['username']
            session['pentester_role'] = user['role']
            session['api_key'] = user['api_key']
            return jsonify({'success': True, 'role': user['role'], 'username': user['username']})
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/profile")
@require_pentester
def get_profile():
    try:
        history = user_manager.get_user_audit_history(session['pentester_id'])
        return jsonify({'success': True, 'profile': {
            'id': session['pentester_id'],
            'username': session['pentester_username'],
            'role': session['pentester_role'],
            'audit_history': history
        }})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/logout")
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route("/admin/users")
@require_admin
def list_users():
    try:
        conn = sqlite3.connect('users.db')
        users = conn.execute('SELECT id, username, email, role, created_at FROM users').fetchall()
        conn.close()
        return jsonify({'success': True, 'users': [
            {'id': u[0], 'username': u[1], 'email': u[2], 'role': u[3], 'created_at': u[4]}
            for u in users
        ]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/active-audits")
@require_pentester
def active_audits():
    return jsonify({'success': True, 'active_count': live_monitor.get_active_audits_count()})

# =========================
# SOCKET.IO EVENTS
# =========================
@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to Pentest Platform'})

@socketio.on('subscribe_audit')
def handle_subscribe(data):
    audit_id = data.get('audit_id')
    if audit_id:
        join_room(f'audit_{audit_id}')
        emit('subscribed', {'audit_id': audit_id})

# =========================
# ERROR HANDLERS
# =========================
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal error'}), 500

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    print("=" * 60)
    print("✅ Professional Pentest Platform v2.0")
    print("=" * 60)
    print("⚠️  Ensure environment variables are set (see .env.example).")
    print("=" * 60)

    port = int(os.environ.get('PORT', '8080'))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    socketio.run(app, debug=debug, port=port, host='0.0.0.0', allow_unsafe_werkzeug=True)