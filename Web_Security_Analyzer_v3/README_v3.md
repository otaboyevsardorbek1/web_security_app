# Web Security Analyzer v3.0

## Professional Pentest Platform - Enhanced Version

### Key Improvements from v2.0

#### Security Enhancements
- **SSRF Protection**: Blocks localhost, private IP ranges, and internal resources
- **Path Traversal Prevention**: Secure file download with directory traversal protection
- **Brute Force Protection**: Account lockout after 5 failed login attempts (30 min lockout)
- **Password Strength Validation**: Enforces strong passwords (8+ chars, uppercase, lowercase, digits, special chars)
- **JWT Authentication**: Dual authentication (session + JWT tokens with refresh)
- **API Key Authentication**: Separate API key system for programmatic access
- **Audit Logging**: Comprehensive audit trail for all actions
- **Input Sanitization**: All user inputs sanitized and validated
- **Security Headers**: Complete set of HTTP security headers via Talisman
- **CORS Protection**: Configurable CORS with proper origin validation
- **CSRF Protection**: Flask-WTF CSRF tokens on all forms
- **Rate Limiting**: Per-endpoint rate limits with Redis support
- **Proxy Fix**: Proper handling of reverse proxy headers

#### Architecture Improvements
- **Configuration Management**: Environment variable based config with .env support
- **Database Manager**: Thread-safe connection pooling with proper indexes
- **Modular Design**: Separate classes for each component
- **Error Handling**: Comprehensive error handlers with proper HTTP status codes
- **Logging**: Structured logging with separate audit log
- **Password Hashing**: PBKDF2-SHA256 with 600,000 iterations

#### Feature Additions
- **Compliance Checks**: PCI DSS, HIPAA, GDPR, SOC 2, ISO 27001, OWASP Top 10
- **Threat Intelligence**: IP reputation checking, domain reputation, DNS analysis
- **Enhanced Scanning**: XSS, SQL Injection, CSRF, SSRF, IDOR, Open Ports, Sensitive Files, SSL/TLS
- **Subdomain Enumeration**: 100+ wordlist with concurrent scanning
- **PDF Reports**: Professional PDF generation with findings and compliance
- **Email Notifications**: SMTP integration for audit completion alerts
- **Real-time Updates**: Socket.IO for live audit progress
- **Pagination**: Audit history with pagination support
- **User Management**: Role-based access control (user, pentester, admin)

#### Database Schema
- **Users Table**: Enhanced with MFA support, lockout, API keys
- **Audit History**: Comprehensive audit tracking with scores
- **Audit Findings**: Detailed finding storage with CVSS/CWE
- **Login Attempts**: Brute force tracking
- **Threat Intel Cache**: Cached threat intelligence
- **API Keys**: Separate API key management

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/web_security_app.git
cd web_security_app

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements_v3.txt

# Copy environment file
cp .env.example .env
# Edit .env with your settings

# Run application
python main_v3.py
```

### Default Credentials
- **Username**: admin
- **Password**: Admin123!
- **Role**: admin

### API Endpoints

#### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/refresh-token` - Refresh JWT token
- `GET /api/logout` - Logout
- `GET /api/profile` - Get user profile

#### Scanning
- `POST /api/analyze` - Quick security analysis
- `POST /api/start-audit` - Start full security audit
- `POST /api/scan-phase` - Run specific scan phase
- `POST /api/subdomain-scan` - Scan subdomains

#### Reports
- `POST /api/generate-report` - Generate PDF report
- `GET /api/download-report/<filename>` - Download report
- `GET /api/audit-history` - Get audit history
- `GET /api/active-audits` - Get active audits

#### Admin
- `GET /api/admin/users` - List all users (admin only)

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| SECRET_KEY | Flask secret key | Auto-generated |
| JWT_SECRET_KEY | JWT signing key | Auto-generated |
| DATABASE_PATH | SQLite database path | users.db |
| RATELIMIT_STORAGE_URI | Rate limit storage | memory:// |
| SMTP_SERVER | SMTP server | smtp.gmail.com |
| SMTP_PORT | SMTP port | 587 |
| SMTP_USERNAME | SMTP username | - |
| SMTP_PASSWORD | SMTP password | - |
| ABUSEIPDB_API_KEY | AbuseIPDB API key | - |
| PORT | Server port | 5000 |
| FLASK_DEBUG | Debug mode | False |

### Security Considerations

1. **Production Deployment**
   - Set `SESSION_COOKIE_SECURE=True` when using HTTPS
   - Use Redis for rate limiting in production
   - Set strong `SECRET_KEY` and `JWT_SECRET_KEY`
   - Enable firewall rules
   - Use reverse proxy (nginx/Apache)

2. **SSL/TLS**
   - Always use HTTPS in production
   - Configure proper SSL certificates
   - Enable HSTS

3. **Rate Limiting**
   - Default: 100 requests/hour
   - Login: 10 requests/minute
   - Registration: 5 requests/hour
   - Audit start: 10 requests/hour

### License
MIT License

### Author
Enhanced by AI based on original work by otaboyevsardorbek1
