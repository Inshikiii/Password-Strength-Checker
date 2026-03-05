================================================================================
SECURE USER REGISTRATION SYSTEM
================================================================================

Student: Nirnaya Shrestha (250700527)
College: ISMT College
Course: Advanced CyberSecurity
Date: February 2026


SECURITY COMPLIANCE CHECKLIST
------------------------------
✓ No hardcoded secrets (all credentials in environment variables)
✓ Password blacklist implemented (top 100 common passwords blocked)
✓ Email format validation (server-side regex validation)
✓ Rate limiting (5 attempts per 5 minutes per IP on registration)
✓ HTTPS deployment guidelines included (see Production Deployment section)
✓ Security event logging (tracks all failed attempts and suspicious activity)
✓ CSRF protection on all forms
✓ bcrypt password hashing
✓ SQL injection prevention (parameterized queries)
✓ Session timeout (30 minutes)
✓ Input sanitization and validation


QUICK START
-----------
1. pip install -r requirements.txt
2. Copy .env.example to .env and add your credentials:
   - SECRET_KEY=generate-with-python-secrets-module
   - EMAIL_ADDRESS=your-email@gmail.com
   - EMAIL_PASSWORD=your-app-password
   
   To generate SECRET_KEY, run:
   python -c "import secrets; print(secrets.token_hex(32))"
   
3. python app.py
4. Go to http://127.0.0.1:5000


WHAT I MADE
-----------
This is a secure user registration web app with multiple security layers.
I implemented:
- Password strength checker (shows Weak/Medium/Strong/Very Strong)
- bcrypt for password hashing
- Email verification with OTP codes
- CAPTCHA to prevent bots
- CSRF protection
- Rate limiting
- Input validation


HOW IT WORKS
------------
1. User fills out registration form (username, email, password)
2. Password must be at least Medium strength to continue
3. System sends 6-digit OTP to their email (expires in 5 minutes)
4. User enters OTP code (gets 3 attempts)
5. User completes CAPTCHA challenge (gets 3 attempts)
6. Account is created and stored in database


PASSWORD STRENGTH ALGORITHM
----------------------------
I made a scoring system (0-6 points):
- Length 8+ chars = 1 point
- Length 12+ chars = 1 bonus point
- Has uppercase = 1 point
- Has lowercase = 1 point
- Has numbers = 1 point
- Has special chars = 1 point

Additional Security Checks:
- Common password blacklist (rejects "password123", "qwerty", etc.)
- Pattern detection (sequential numbers like "123", "234")
- Repeated characters (like "aaa", "111")
- Keyboard patterns (like "qwerty", "asdf")
- Common substitutions (like "p@ssw0rd")

Results:
- 0-2 points = Weak (rejected)
- 3-4 points = Medium (accepted)
- 5 points = Strong (accepted)
- 6 points = Very Strong (accepted)


SECURITY FEATURES I IMPLEMENTED
--------------------------------
✓ bcrypt password hashing (not plain text)
✓ Email OTP verification (real emails sent)
✓ Server-side validation (not just client-side)
✓ SQL injection prevention (parameterized queries)
✓ CSRF tokens on all forms
✓ Rate limiting on registration (5 attempts per 5 minutes per IP)
✓ Rate limiting on CAPTCHA (15 second lockout after 3 failed attempts)
✓ Rate limiting on OTP (3 attempts max, 5 minute expiration)
✓ Session timeout (30 minutes)
✓ Input sanitization (username only allows alphanumeric + underscore)
✓ Environment variables for sensitive credentials (no hardcoded passwords)
✓ Unique email enforcement (prevents duplicate accounts)
✓ Common password blacklist (rejects weak passwords)
✓ Pattern detection (sequential numbers, repeated chars, keyboard patterns)
✓ Security event logging (tracks failed attempts and suspicious activity)


PROJECT FILES
-------------
app.py              - Main Flask application
database_schema.sql - Database schema documentation
security.log        - Security event log (auto-generated)
templates/          - HTML pages (index, register, verify, captcha, success)
static/             - CSS and JavaScript files
requirements.txt    - Python dependencies
.env.example        - Environment variables template
.gitignore          - Files to exclude from version control
README.txt          - This file

Note: users.db is created automatically when you first run the app


TECHNICAL DETAILS
-----------------
- Framework: Flask (Python)
- Database: SQLite
- Password Hashing: bcrypt
- Email: Gmail SMTP (sends from ISMT Secure Registration)
- Session Storage: In-memory (server-side)
- Secret Key: Loaded from environment variable (cryptographically secure)
- Frontend: HTML, CSS, JavaScript with animated matrix background


TESTING THE APP
---------------
1. Register with any email address
2. Check that email's inbox for the OTP code
3. Enter the OTP within 5 minutes
4. Complete the CAPTCHA
5. See success page with registration details

Note: Emails are sent from "ISMT Secure Registration - No Reply"
Check spam folder if you don't see the email.


CHALLENGES I FACED
------------------
- Setting up Gmail SMTP with App Passwords
- Managing sessions across multiple pages
- Making sure OTP expires after 5 minutes
- Implementing rate limiting for CAPTCHA attempts
- Creating a real-time password strength checker
- Building common password blacklist
- Detecting simple patterns in passwords


WHAT I LEARNED
--------------
- How to implement secure authentication flows
- Email verification using SMTP protocols
- Password hashing with bcrypt
- CSRF protection techniques
- Session management best practices
- SQL injection prevention
- Environment variables for sensitive data
- Proper database schema design
- Not committing sensitive files to version control
- Security event logging and monitoring


SECURITY LOGGING
----------------
The system logs all security-related events to security.log:
- Failed OTP attempts (tracks IP, email, attempt count)
- Failed CAPTCHA attempts (tracks IP, email, attempt count)
- Rate limit violations (tracks IP, endpoint, cooldown time)
- CAPTCHA lockouts (15 second lockouts after 3 failures)
- OTP lockouts (max 3 attempts per session)
- Successful registrations (tracks IP, username, email)

Log Format: YYYY-MM-DD HH:MM:SS - WARNING - [EVENT_TYPE] IP: x.x.x.x - Details

This helps identify:
- Brute force attacks
- Bot activity
- Suspicious registration patterns
- System abuse attempts


PRODUCTION DEPLOYMENT RECOMMENDATIONS
--------------------------------------
For production deployment, the following security measures are essential:

1. HTTPS/TLS Configuration:
   - Deploy behind a reverse proxy (nginx, Apache) with SSL/TLS certificates
   - Use Let's Encrypt for free SSL certificates or purchase from trusted CA
   - Enforce HTTPS-only traffic (redirect HTTP to HTTPS)
   - Enable HSTS (HTTP Strict Transport Security) headers
   - Configure secure cookie flags (Secure, HttpOnly, SameSite)

2. Environment Configuration:
   - Set Flask to production mode (disable debug)
   - Use production-grade WSGI server (Gunicorn, uWSGI)
   - Configure proper firewall rules
   - Use environment-specific .env files
   - Never expose .env or security.log files publicly

3. Database Security:
   - Migrate from SQLite to PostgreSQL/MySQL for production
   - Use connection pooling
   - Regular database backups
   - Implement database encryption at rest

4. Additional Security Headers:
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - Content-Security-Policy
   - X-XSS-Protection: 1; mode=block

5. Monitoring and Maintenance:
   - Regular security log reviews
   - Automated intrusion detection
   - Keep dependencies updated
   - Regular security audits

Example nginx HTTPS configuration:
```
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Host $host;
    }
}
```

Note: This application is designed for educational purposes. For production use,
implement all recommended security measures and conduct thorough security testing.


SECURITY BEST PRACTICES FOLLOWED
---------------------------------
✓ No hardcoded credentials in source code
✓ Environment variables for sensitive data
✓ Database created dynamically (not included in repo)
✓ .gitignore prevents committing sensitive files (*.db, .env, *.log)
✓ Password hashes only (never plain text)
✓ Documented database schema separately
✓ Security event logging for audit trails


================================================================================
