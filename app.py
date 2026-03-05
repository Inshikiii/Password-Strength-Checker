"""
Secure User Registration System
Advanced CyberSecurity University Assignment

Student Name: Nirnaya Shrestha
Student ID: 250700527
Institution: ISMT College
Course: Advanced CyberSecurity
Date: February 2026

This Flask application demonstrates secure system design principles including:
- Secure password hashing using bcrypt
- Server-side validation and sanitization
- CAPTCHA implementation for bot prevention
- Password strength evaluation algorithm
- Secure server-side session management
- CSRF protection for form submissions
"""

from flask import Flask, render_template, request, session, jsonify
import sqlite3
import bcrypt
import random
import re
import os
import secrets
import hashlib
from datetime import timedelta, datetime
import time
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database Configuration
# Use absolute path to prevent issues when running from different directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'users.db')

app = Flask(__name__)
# SECURITY: Secret key from environment variable with secure fallback
# For production, always set SECRET_KEY in .env file
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Configure session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email Configuration (Gmail SMTP)
# SECURITY: Credentials loaded from environment variables to prevent exposure
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', 'your-email@gmail.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'your-app-password')

# In-memory session store
SESSION_STORE = {}

# Rate limiting store (tracks registration attempts by IP)
RATE_LIMIT_STORE = {}

# Configure security logging
logging.basicConfig(
    filename='security.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
security_logger = logging.getLogger('security')

def log_security_event(event_type, ip_address, details):
    """Log security-related events for monitoring and auditing"""
    security_logger.warning(f"[{event_type}] IP: {ip_address} - {details}")

def cleanup_old_sessions():
    """Remove expired sessions from store"""
    current_time = time.time()
    expired = [sid for sid, data in SESSION_STORE.items() 
               if current_time - data.get('created_at', 0) > 1800]  # 30 minutes
    for sid in expired:
        SESSION_STORE.pop(sid, None)

def cleanup_rate_limits():
    """Remove expired rate limit entries"""
    current_time = time.time()
    expired = [ip for ip, data in RATE_LIMIT_STORE.items() 
               if current_time - data.get('last_attempt', 0) > 300]  # 5 minutes
    for ip in expired:
        RATE_LIMIT_STORE.pop(ip, None)

def check_rate_limit(ip_address, max_attempts=5, window_seconds=300):
    """
    Check if IP has exceeded rate limit
    
    Args:
        ip_address: Client IP address
        max_attempts: Maximum attempts allowed (default: 5)
        window_seconds: Time window in seconds (default: 300 = 5 minutes)
    
    Returns:
        tuple: (is_allowed, remaining_attempts, retry_after_seconds)
    """
    cleanup_rate_limits()
    current_time = time.time()
    
    if ip_address not in RATE_LIMIT_STORE:
        RATE_LIMIT_STORE[ip_address] = {
            'attempts': 1,
            'first_attempt': current_time,
            'last_attempt': current_time
        }
        return (True, max_attempts - 1, 0)
    
    rate_data = RATE_LIMIT_STORE[ip_address]
    time_passed = current_time - rate_data['first_attempt']
    
    # Reset if window has passed
    if time_passed > window_seconds:
        RATE_LIMIT_STORE[ip_address] = {
            'attempts': 1,
            'first_attempt': current_time,
            'last_attempt': current_time
        }
        return (True, max_attempts - 1, 0)
    
    # Check if limit exceeded
    if rate_data['attempts'] >= max_attempts:
        retry_after = int(window_seconds - time_passed)
        return (False, 0, retry_after)
    
    # Increment attempts
    rate_data['attempts'] += 1
    rate_data['last_attempt'] = current_time
    remaining = max_attempts - rate_data['attempts']
    
    return (True, remaining, 0)

def get_session_id():
    """Get or create session ID"""
    if 'sid' not in session:
        session['sid'] = secrets.token_hex(16)
        session.permanent = True
    return session['sid']

def store_session_data(key, value):
    """Store data in session store"""
    cleanup_old_sessions()
    sid = get_session_id()
    if sid not in SESSION_STORE:
        SESSION_STORE[sid] = {'created_at': time.time()}
    SESSION_STORE[sid][key] = value

def get_session_data(key, default=None):
    """Retrieve data from session store"""
    sid = session.get('sid')
    if not sid or sid not in SESSION_STORE:
        return default
    return SESSION_STORE[sid].get(key, default)

def clear_session_data():
    """Clear session data"""
    sid = session.get('sid')
    if sid and sid in SESSION_STORE:
        SESSION_STORE.pop(sid, None)

# Make all sessions permanent by default
@app.before_request
def make_session_permanent():
    session.permanent = True

# Database initialization
def init_db():
    """Initialize SQLite database with users table"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def generate_csrf_token():
    """
    Generate a secure CSRF token
    
    CSRF (Cross-Site Request Forgery) Protection:
    - Prevents malicious websites from submitting forms on behalf of users
    - Token is unique per session and validated server-side
    - Uses cryptographically secure random generation
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """
    Validate CSRF token against session token
    
    Uses constant-time comparison to prevent timing attacks
    """
    session_token = session.get('csrf_token')
    if not session_token or not token:
        return False
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(session_token, token)

def calculate_password_entropy(password):
    """
    Calculate password entropy in bits
    
    Entropy Formula: E = log2(N^L)
    Where:
    - N = size of character pool
    - L = length of password
    
    Character pools:
    - Lowercase: 26 characters
    - Uppercase: 26 characters
    - Digits: 10 characters
    - Special: ~32 common special characters
    
    Returns: entropy value in bits (float)
    """
    import math
    
    pool_size = 0
    
    # Determine character pool size based on what's used
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'\d', password):
        pool_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        pool_size += 32
    
    # Calculate entropy: log2(pool_size^length)
    if pool_size > 0:
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 1)
    
    return 0.0

def check_common_password(password):
    """
    Check if password is in common password blacklist
    Returns True if password is common (should be rejected)
    """
    # Common passwords list (top 100 most common passwords)
    common_passwords = {
        'password', 'password123', '123456', '12345678', '123456789', 'qwerty',
        'abc123', 'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley', 'bailey',
        'passw0rd', 'shadow', '123123', '654321', 'superman', 'qazwsx',
        'michael', 'football', 'welcome', 'jesus', 'ninja', 'mustang',
        'password1', '123qwe', 'admin', 'admin123', 'root', 'toor',
        'pass', 'test', 'guest', 'info', 'adm', 'mysql', 'user',
        'administrator', 'oracle', 'ftp', 'pi', 'puppet', 'ansible',
        'ec2-user', 'vagrant', 'azureuser', 'P@ssw0rd', 'P@ssword123',
        'Password1', 'Password123', 'Welcome123', 'Qwerty123'
    }
    
    # Check case-insensitive
    return password.lower() in common_passwords

def check_simple_patterns(password):
    """
    Check for simple patterns that make passwords weak
    Returns list of detected patterns
    """
    patterns = []
    
    # Check for sequential numbers (123, 234, etc.)
    if re.search(r'(012|123|234|345|456|567|678|789)', password):
        patterns.append("Sequential numbers detected")
    
    # Check for repeated characters (aaa, 111, etc.)
    if re.search(r'(.)\1{2,}', password):
        patterns.append("Repeated characters detected")
    
    # Check for keyboard patterns (qwerty, asdf, etc.)
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl']
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            patterns.append("Keyboard pattern detected")
            break
    
    # Check for common substitutions (@ for a, 3 for e, etc.) with common words
    common_with_subs = ['p@ssw0rd', 'p@ssword', 'passw0rd', 'l3tm3in', 'w3lc0me']
    if password.lower() in common_with_subs:
        patterns.append("Common word with simple substitutions")
    
    return patterns

def calculate_password_strength(password):
    """
    Enhanced algorithm to evaluate password strength
    
    Scoring System:
    - Length >= 8: +1 point
    - Length >= 12: +1 bonus point
    - Contains uppercase: +1 point
    - Contains lowercase: +1 point
    - Contains digit: +1 point
    - Contains special character: +1 point
    
    Additional Checks:
    - Common password blacklist
    - Simple pattern detection
    - Sequential characters
    - Repeated characters
    
    Classification:
    - 0-2 points: Weak
    - 3-4 points: Medium
    - 5-6 points: Strong
    
    Returns: dict with score, strength level, feedback, and entropy
    """
    score = 0
    feedback = []
    
    # Check for common passwords first (instant reject)
    if check_common_password(password):
        return {
            'score': 0,
            'max_score': 6,
            'strength': 'weak',
            'strength_text': 'Weak',
            'feedback': ['✗ Password is too common and easily guessable'],
            'entropy': 0.0
        }
    
    # Check for simple patterns
    patterns = check_simple_patterns(password)
    if patterns:
        for pattern in patterns:
            feedback.append(f"✗ {pattern}")
        # Reduce score for patterns but don't auto-reject
        score -= 1
    
    # Length checks
    if len(password) >= 8:
        score += 1
        feedback.append("✓ Minimum length met")
    else:
        feedback.append("✗ Password too short (minimum 8 characters)")
    
    if len(password) >= 12:
        score += 1
        feedback.append("✓ Excellent length (12+ characters)")
    
    # Character type checks
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append("✓ Contains uppercase letter")
    else:
        feedback.append("✗ Missing uppercase letter")
    
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append("✓ Contains lowercase letter")
    else:
        feedback.append("✗ Missing lowercase letter")
    
    if re.search(r'\d', password):
        score += 1
        feedback.append("✓ Contains number")
    else:
        feedback.append("✗ Missing number")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
        feedback.append("✓ Contains special character")
    else:
        feedback.append("✗ Missing special character")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    # Classify strength
    if score <= 2:
        strength = "weak"
        strength_text = "Weak"
    elif score <= 4:
        strength = "medium"
        strength_text = "Medium"
    elif score == 5:
        strength = "strong"
        strength_text = "Strong"
    else:  # score == 6
        strength = "very-strong"
        strength_text = "Very Strong"
    
    # Calculate actual entropy
    entropy = calculate_password_entropy(password)
    
    return {
        'score': score,
        'max_score': 6,
        'strength': strength,
        'strength_text': strength_text,
        'feedback': feedback,
        'entropy': entropy
    }

def sanitize_username(username):
    """
    Sanitize username input to prevent injection attacks
    Only allow alphanumeric characters and underscores
    """
    return re.sub(r'[^\w]', '', username)

def hash_password(password):
    """
    Hash password using bcrypt
    
    Why bcrypt?
    - Designed specifically for password hashing
    - Includes built-in salt generation
    - Computationally expensive (resistant to brute-force)
    - Adaptive: can increase cost factor as hardware improves
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def check_username_exists(username):
    """Check if username already exists in database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def check_email_exists(email):
    """Check if email already exists in database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def generate_otp():
    """Generate 6-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_otp_email(to_email, otp_code):
    """Send OTP via email using Gmail SMTP"""
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Your Verification Code - Secure Registration'
        msg['From'] = f'ISMT Secure Registration - No Reply <{EMAIL_ADDRESS}>'  # Custom sender name
        msg['To'] = to_email
        
        # HTML email body
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #0a0e1b; color: #ffffff; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1a1f35; border: 1px solid #00ff88; border-radius: 10px; padding: 30px;">
                <h1 style="color: #00ff88; text-align: center;">🔒 Email Verification</h1>
                <p style="font-size: 16px; line-height: 1.6;">Hello,</p>
                <p style="font-size: 16px; line-height: 1.6;">Your verification code for account registration is:</p>
                <div style="background-color: #0a0e1b; border: 2px solid #00ff88; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                    <h2 style="color: #00ff88; font-size: 36px; letter-spacing: 8px; margin: 0;">{otp_code}</h2>
                </div>
                <p style="font-size: 14px; line-height: 1.6; color: #a0a0a0;">
                    ⏰ This code will expire in <strong style="color: #00ff88;">5 minutes</strong><br>
                    🔐 You have <strong style="color: #00ff88;">3 attempts</strong> to enter the correct code
                </p>
                <p style="font-size: 14px; line-height: 1.6; color: #a0a0a0; margin-top: 30px;">
                    If you didn't request this code, please ignore this email.
                </p>
                <hr style="border: none; border-top: 1px solid #2a2f45; margin: 20px 0;">
                <p style="font-size: 12px; color: #6b7280; text-align: center;">
                    Secure User Registration System<br>
                    Advanced CyberSecurity Project
                </p>
            </div>
        </body>
        </html>
        """
        
        # Attach HTML content
        msg.attach(MIMEText(html, 'html'))
        
        # Send email
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to send email: {e}")
        return False

def validate_email(email):
    """Validate email format using regex"""
    EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"
    return re.match(EMAIL_REGEX, email) is not None


@app.route('/')
def index():
    """Welcome landing page"""
    return render_template('index.html')

@app.route('/register')
def register_page():
    """Main registration page"""
    csrf_token = generate_csrf_token()
    return render_template('register.html', csrf_token=csrf_token)

@app.route('/store_registration', methods=['POST'])
def store_registration():
    """
    Store registration data and send OTP email
    Rate limited to prevent brute-force attacks
    """
    try:
        # Get client IP address
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        # Check rate limit (5 attempts per 5 minutes per IP)
        is_allowed, remaining, retry_after = check_rate_limit(client_ip, max_attempts=5, window_seconds=300)
        
        if not is_allowed:
            log_security_event('RATE_LIMIT_EXCEEDED', client_ip, 
                             f'Registration endpoint - {retry_after}s cooldown')
            return jsonify({
                'success': False,
                'message': f'Too many registration attempts. Please try again in {retry_after} seconds.',
                'retry_after': retry_after
            }), 429
        
        data = request.get_json()
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        csrf_token = data.get('csrf_token', '')
        
        # Validate CSRF token
        if not validate_csrf_token(csrf_token):
            return jsonify({
                'success': False,
                'message': 'Invalid security token. Please refresh the page and try again.'
            }), 403
        
        # Validate inputs
        if not username or not email or not password:
            return jsonify({
                'success': False,
                'message': 'All fields are required'
            }), 400
        
        # Validate email format
        if not validate_email(email):
            return jsonify({
                'success': False,
                'message': 'Invalid email address'
            }), 400
        
        # Sanitize username
        username = sanitize_username(username)
        
        # Validate username length
        if len(username) < 3 or len(username) > 20:
            return jsonify({
                'success': False,
                'message': 'Invalid username format'
            }), 400
        
        # Check password strength
        strength_info = calculate_password_strength(password)
        if strength_info['strength'] == 'weak':
            return jsonify({
                'success': False,
                'message': 'Password does not meet security requirements'
            }), 400
        
        # Check for duplicate username
        if check_username_exists(username):
            return jsonify({
                'success': False,
                'message': 'Username not available'
            }), 400
        
        # Check for duplicate email
        if check_email_exists(email):
            return jsonify({
                'success': False,
                'message': 'Email address already registered'
            }), 400
        
        # Generate OTP
        otp = generate_otp()
        otp_timestamp = time.time()
        
        # Send OTP email
        if not send_otp_email(email, otp):
            return jsonify({
                'success': False,
                'message': 'Failed to send verification email. Please check your email address.'
            }), 500
        
        # Store in session store (server-side in-memory)
        store_session_data('pending_username', username)
        store_session_data('pending_email', email)
        store_session_data('pending_password', password)
        store_session_data('password_strength_info', strength_info)
        store_session_data('otp_code', otp)
        store_session_data('otp_timestamp', otp_timestamp)
        store_session_data('otp_attempts', 0)
        
        return jsonify({
            'success': True,
            'message': 'Verification code sent to your email!'
        })
        
    except Exception as e:
        print(f"Error in store_registration: {e}")
        return jsonify({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }), 500



@app.route('/verify')
def verify_page():
    """Email OTP verification page"""
    # Check if registration data exists
    if not get_session_data('pending_username'):
        return render_template('register.html', csrf_token=generate_csrf_token())
    
    csrf_token = generate_csrf_token()
    email = get_session_data('pending_email', '')
    # Mask email for display
    if '@' in email:
        parts = email.split('@')
        masked_email = parts[0][:2] + '***@' + parts[1]
    else:
        masked_email = '***'
    
    return render_template('verify.html', csrf_token=csrf_token, masked_email=masked_email)

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    """Verify OTP code"""
    try:
        data = request.get_json()
        otp_input = data.get('otp', '').strip()
        csrf_token = data.get('csrf_token', '')
        
        # Validate CSRF token
        if not validate_csrf_token(csrf_token):
            return jsonify({
                'success': False,
                'message': 'Invalid security token.'
            }), 403
        
        # Check session data
        if not get_session_data('otp_code'):
            return jsonify({
                'success': False,
                'message': 'Session expired. Please register again.'
            }), 400
        
        # Check OTP attempts
        otp_attempts = get_session_data('otp_attempts', 0)
        if otp_attempts >= 3:
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            log_security_event('OTP_LOCKED', client_ip, 
                             f'Max OTP attempts exceeded - Email: {get_session_data("email", "unknown")}')
            return jsonify({
                'success': False,
                'message': 'Too many failed attempts. Please register again.',
                'locked': True
            }), 429
        
        # Check OTP expiration (5 minutes)
        otp_timestamp = get_session_data('otp_timestamp', 0)
        if time.time() - otp_timestamp > 300:  # 5 minutes
            return jsonify({
                'success': False,
                'message': 'Verification code expired. Please register again.',
                'expired': True
            }), 400
        
        # Validate OTP
        stored_otp = get_session_data('otp_code')
        if otp_input != stored_otp:
            store_session_data('otp_attempts', otp_attempts + 1)
            remaining = 3 - (otp_attempts + 1)
            
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            log_security_event('OTP_FAILED', client_ip, 
                             f'Incorrect OTP - Attempt {otp_attempts + 1}/3 - Email: {get_session_data("email", "unknown")}')
            
            return jsonify({
                'success': False,
                'message': f'Incorrect code. {remaining} attempts remaining.',
                'attempts_remaining': remaining
            }), 400
        
        # OTP verified successfully
        store_session_data('otp_verified', True)
        
        return jsonify({
            'success': True,
            'message': 'Email verified successfully!',
            'redirect': '/captcha'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }), 500

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    """Resend OTP code"""
    try:
        csrf_token = request.get_json().get('csrf_token', '')
        
        # Validate CSRF token
        if not validate_csrf_token(csrf_token):
            return jsonify({
                'success': False,
                'message': 'Invalid security token.'
            }), 403
        
        # Check session data
        email = get_session_data('pending_email')
        if not email:
            return jsonify({
                'success': False,
                'message': 'Session expired. Please register again.'
            }), 400
        
        # Generate new OTP
        otp = generate_otp()
        otp_timestamp = time.time()
        
        # Send OTP email
        if not send_otp_email(email, otp):
            return jsonify({
                'success': False,
                'message': 'Failed to send email. Please try again.'
            }), 500
        
        # Update session
        store_session_data('otp_code', otp)
        store_session_data('otp_timestamp', otp_timestamp)
        store_session_data('otp_attempts', 0)
        
        return jsonify({
            'success': True,
            'message': 'New verification code sent to your email.'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'An error occurred. Please try again.'
        }), 500

@app.route('/captcha')
def captcha_page():
    """CAPTCHA verification page (after OTP verification)"""
    # Check if OTP was verified
    if not get_session_data('otp_verified'):
        return render_template('register.html', csrf_token=generate_csrf_token())
    
    # Check session data
    username = get_session_data('pending_username')
    email = get_session_data('pending_email')
    password = get_session_data('pending_password')
    
    # If session data is missing, redirect back to registration
    if not username or not email or not password:
        return render_template('register.html', csrf_token=generate_csrf_token())
    
    # Check if account is temporarily locked due to failed CAPTCHA attempts
    failed_attempts = get_session_data('captcha_failed_attempts', 0)
    lockout_time = get_session_data('captcha_lockout_until', 0)
    
    if failed_attempts >= 3:
        current_time = time.time()
        if current_time < lockout_time:
            # Still locked out
            remaining_seconds = int(lockout_time - current_time)
            return render_template('captcha.html', 
                                 csrf_token=generate_csrf_token(),
                                 locked_out=True,
                                 remaining_seconds=remaining_seconds)
        else:
            # Lockout expired, reset attempts
            store_session_data('captcha_failed_attempts', 0)
            store_session_data('captcha_lockout_until', None)
    
    csrf_token = generate_csrf_token()
    return render_template('captcha.html', csrf_token=csrf_token, locked_out=False)

@app.route('/captcha_image')
def captcha_image():
    """Generate CAPTCHA image"""
    from PIL import Image, ImageDraw, ImageFont
    import io
    import random
    import string
    
    # Generate random text
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    store_session_data('captcha_answer', captcha_text)
    
    # Create image
    width, height = 200, 80
    image = Image.new('RGB', (width, height), color=(240, 240, 240))
    draw = ImageDraw.Draw(image)
    
    # Add noise lines
    for _ in range(5):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(200, 200, 200), width=1)
    
    # Add noise dots
    for _ in range(100):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(180, 180, 180))
    
    # Draw text
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        font = ImageFont.load_default()
    
    # Draw each character with random position and rotation
    x_offset = 10
    for char in captcha_text:
        # Random color (dark)
        color = (random.randint(0, 100), random.randint(0, 100), random.randint(0, 100))
        
        # Draw character
        draw.text((x_offset, random.randint(10, 20)), char, font=font, fill=color)
        x_offset += 30
    
    # Save to bytes
    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)
    
    from flask import send_file
    return send_file(img_io, mimetype='image/png')

@app.route('/complete_registration', methods=['POST'])
def complete_registration():
    """Complete registration after CAPTCHA verification"""
    try:
        captcha_input = request.form.get('captcha', '').strip()
        csrf_token = request.form.get('csrf_token', '')
        
        # Validate CSRF token
        if not validate_csrf_token(csrf_token):
            return jsonify({
                'success': False,
                'message': 'Invalid security token. Please refresh the page and try again.'
            }), 403
        
        # Check if temporarily locked out
        failed_attempts = get_session_data('captcha_failed_attempts', 0)
        lockout_time = get_session_data('captcha_lockout_until', 0)
        
        if failed_attempts >= 3:
            current_time = time.time()
            if current_time < lockout_time:
                remaining_seconds = int(lockout_time - current_time)
                
                client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                if client_ip:
                    client_ip = client_ip.split(',')[0].strip()
                log_security_event('CAPTCHA_LOCKED', client_ip, 
                                 f'CAPTCHA lockout active - {remaining_seconds}s remaining - Email: {get_session_data("pending_email", "unknown")}')
                
                return jsonify({
                    'success': False,
                    'message': f'Too many failed attempts. Please wait {remaining_seconds} seconds before trying again.',
                    'locked_out': True,
                    'remaining_seconds': remaining_seconds
                }), 429
            else:
                # Lockout expired, reset attempts
                store_session_data('captcha_failed_attempts', 0)
                store_session_data('captcha_lockout_until', None)
                failed_attempts = 0
        
        # Retrieve registration data from session store
        username = get_session_data('pending_username')
        email = get_session_data('pending_email')
        password = get_session_data('pending_password')
        strength_info = get_session_data('password_strength_info')
        
        # Validate session data exists
        if not username or not email or not password:
            return jsonify({
                'success': False,
                'message': 'Session expired. Please try again.'
            }), 400
        
        # CRITICAL: Re-validate password strength server-side (defense-in-depth)
        # This ensures weak passwords are rejected even if session is manipulated
        recalculated_strength = calculate_password_strength(password)
        if recalculated_strength['strength'] == 'weak':
            # Clear invalid session data
            clear_session_data()
            return jsonify({
                'success': False,
                'message': 'Invalid registration data. Please try again.'
            }), 400
        
        # Validate CAPTCHA
        captcha_answer = get_session_data('captcha_answer')
        if not captcha_answer or captcha_input.upper() != captcha_answer:
            # Increment failed attempts
            failed_attempts += 1
            store_session_data('captcha_failed_attempts', failed_attempts)
            
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            log_security_event('CAPTCHA_FAILED', client_ip, 
                             f'Incorrect CAPTCHA - Attempt {failed_attempts}/3 - Email: {get_session_data("pending_email", "unknown")}')
            
            # Lock out after 3 failed attempts (15 seconds)
            if failed_attempts >= 3:
                store_session_data('captcha_lockout_until', time.time() + 15)
                log_security_event('CAPTCHA_LOCKOUT_TRIGGERED', client_ip, 
                                 f'15 second lockout initiated - Email: {get_session_data("pending_email", "unknown")}')
                return jsonify({
                    'success': False,
                    'message': 'Too many failed CAPTCHA attempts. Account temporarily locked for 15 seconds.',
                    'locked_out': True,
                    'remaining_seconds': 15
                }), 429
            
            return jsonify({
                'success': False,
                'message': f'Incorrect CAPTCHA. Attempt {failed_attempts}/3. Please try again.',
                'attempts_remaining': 3 - failed_attempts
            }), 400
        
        # CAPTCHA correct - reset failed attempts
        store_session_data('captcha_failed_attempts', 0)
        store_session_data('captcha_lockout_until', None)
        
        # Hash password
        password_hash = hash_password(password)
        
        # Store user in database FIRST (before clearing session)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()
        
        # Log successful registration
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if client_ip:
            client_ip = client_ip.split(',')[0].strip()
        log_security_event('REGISTRATION_SUCCESS', client_ip, 
                         f'User registered - Username: {username} - Email: {email}')
        
        print(f"✓ User stored in database - Username: {username}")
        
        # Store display info in regular session (use recalculated values for accuracy)
        session['registered_username'] = username
        session['password_strength'] = f"{recalculated_strength['strength_text']} ({recalculated_strength['score'] * 16}/100)"
        session['password_entropy'] = str(recalculated_strength['entropy'])
        session['password_hash_display'] = password_hash.decode('utf-8')[:40] + '...'
        session['captcha_attempts'] = failed_attempts  # Store for display on success page
        
        # Clear pending registration data from session store (AFTER successful DB insert)
        clear_session_data()
        
        return jsonify({
            'success': True,
            'message': 'Registration successful!',
            'redirect': '/success'
        })
        
    except Exception as e:
        # Log error internally without exposing details to user
        print(f"✗ EXCEPTION in complete_registration: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': 'Unable to complete registration. Please try again.'
        }), 500

@app.route('/check_password_strength', methods=['POST'])
def check_password_strength():
    """
    API endpoint for real-time password strength checking
    Server-side validation ensures security even if client-side is bypassed
    """
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    strength_info = calculate_password_strength(password)
    return jsonify(strength_info)

@app.route('/success')
def success_page():
    """Success page after registration"""
    username = session.get('registered_username', 'User')
    password_strength = session.get('password_strength', 'Strong')
    entropy = session.get('password_entropy', '0.0')
    password_hash = session.get('password_hash_display', '$efecbe7e9eba8342dc314d17afb943...')
    
    return render_template('success.html', 
                         username=username,
                         password_strength=password_strength,
                         entropy=entropy,
                         password_hash=password_hash)

# Error handlers to prevent information disclosure
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors without revealing internal structure"""
    return jsonify({
        'success': False,
        'message': 'Page not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors without revealing stack traces"""
    return jsonify({
        'success': False,
        'message': 'An error occurred. Please try again.'
    }), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Catch-all handler to prevent stack trace disclosure"""
    # Log the error internally (in production, use proper logging)
    # print(f"Error: {error}")  # Only for development
    return jsonify({
        'success': False,
        'message': 'An unexpected error occurred. Please try again.'
    }), 500

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    print("\n" + "="*60)
    print("🚀 Starting Flask Application...")
    print("="*60)
    print("📍 Server will be available at: http://127.0.0.1:5000")
    print("📍 Or visit: http://localhost:5000")
    print("="*60 + "\n")
    # Run Flask application
    # Note: In production, use a proper WSGI server like Gunicorn
    # Debug mode enabled for development
    app.run(debug=True, host='127.0.0.1', port=5000)
