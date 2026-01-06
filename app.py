import qrcode
# pyright: reportAttributeAccessIssue=false, reportOptionalContextManager=false, reportIncompatibleMethodOverride=false, reportArgumentType=false, reportGeneralTypeIssues=false, reportPossiblyUnboundVariable=false, reportCallIssue=false
import io
import smtplib
from email.message import EmailMessage
from email.mime.image import MIMEImage  # Import MIMEImage
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, send_from_directory, abort, session, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import QueuePool
import re # Added for regex operations
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo # Import ZoneInfo for timezone handling
import os
import qrcode
import io
import csv
import random
import openpyxl  # Import openpyxl for Excel export
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import base64
from config import Config
from flask_wtf.csrf import CSRFProtect
from uuid import uuid4
import logging  # Import logging
import html
import time
from functools import wraps
import secrets
from PIL import Image, ImageDraw, ImageFont
import urllib.request
from threading import Thread


def _ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _download_asset(url, dest, timeout=10):
    try:
        _ensure_dir(os.path.dirname(dest))
        if not os.path.exists(dest):
            with urllib.request.urlopen(url, timeout=timeout) as r, open(dest, 'wb') as f:
                f.write(r.read())
            logging.info(f"Downloaded asset: {url} -> {dest}")
    except Exception as e:
        logging.warning(f"Asset download failed: {url} -> {dest} ({e})")


def _prime_local_assets():
    if os.environ.get('ASSETS_LOCAL', '1') not in ('1', 'true', 'True'):
        return
    base = os.path.join('static', 'vendor')
    # Bootstrap
    _download_asset(
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
        os.path.join(base, 'bootstrap', 'css', 'bootstrap.min.css')
    )
    _download_asset(
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
        os.path.join(base, 'bootstrap', 'js', 'bootstrap.bundle.min.js')
    )
    # Font Awesome CSS + webfonts
    fa_css_local = os.path.join(base, 'fontawesome', 'css', 'all.min.css')
    _download_asset(
        'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css',
        fa_css_local
    )
    try:
        if os.path.exists(fa_css_local):
            with open(fa_css_local, 'rb') as f:
                css = f.read().decode('utf-8', errors='ignore')
            import re as _re
            for m in _re.finditer(r"url\(['\"]?\.\./webfonts/([^'\")]+)['\"]?\)", css):
                fname = m.group(1)
                src = f"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/{fname}"
                dst = os.path.join(base, 'fontawesome', 'webfonts', fname)
                _download_asset(src, dst)
    except Exception as e:
        logging.warning(f"FontAwesome webfonts prime failed: {e}")
    # Select2
    _download_asset(
        'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css',
        os.path.join(base, 'select2', 'css', 'select2.min.css')
    )
    _download_asset(
        'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js',
        os.path.join(base, 'select2', 'js', 'select2.min.js')
    )
    # jQuery for Select2
    _download_asset(
        'https://code.jquery.com/jquery-3.6.0.min.js',
        os.path.join(base, 'jquery', 'jquery-3.6.0.min.js')
    )

# Define IST timezone
IST_TIMEZONE = ZoneInfo("Asia/Kolkata")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


app = Flask(__name__, static_url_path='/vms/static')
app.config.from_object(Config)
# Disable debug by default; allow enabling via FLASK_DEBUG env
app.debug = bool(os.environ.get('FLASK_DEBUG', '0').lower() in ['1', 'true'])
app.config['DEBUG'] = app.debug
logging.info("Application configuration initialized.")

# CSRF protection
csrf = CSRFProtect(app)

# Try to prime local vendor assets (CSS/JS)
try:
    _prime_local_assets()
except Exception as _e:
    logging.warning(f"Local asset priming failed: {_e}")

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
from flask_migrate import Migrate

migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore

# Basic in-memory login attempt throttling
LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60

def _login_key(email):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'unknown'
    return f"{ip}:{(email or '').lower()}"

def _is_locked(email):
    from time import time
    k = _login_key(email)
    data = LOGIN_ATTEMPTS.get(k)
    if not data:
        return False
    count, first_ts = data
    if count >= MAX_ATTEMPTS and time() - first_ts < LOCKOUT_SECONDS:
        return True
    if time() - first_ts >= LOCKOUT_SECONDS:
        LOGIN_ATTEMPTS.pop(k, None)
    return False

def _record_attempt(email, success):
    from time import time
    k = _login_key(email)
    if success:
        LOGIN_ATTEMPTS.pop(k, None)
        return
    count, first_ts = LOGIN_ATTEMPTS.get(k, (0, time()))
    LOGIN_ATTEMPTS[k] = (count + 1, first_ts)


def h(val):
    try:
        return html.escape(str(val)) if val is not None else ''
    except Exception:
        return ''

# Simple in-memory token bucket rate limiter
_RATE_BUCKETS = {}
_RATE_LOCK = None
try:
    import threading
    _RATE_LOCK = threading.Lock()
except Exception:
    class _Dummy:
        def __enter__(self):
            return None
        def __exit__(self, exc_type, exc, tb):
            return False
    _RATE_LOCK = _Dummy()


def _rate_key(name: str):
    try:
        identifier = None
        if current_user.is_authenticated:
            identifier = f"user:{current_user.id}"
        else:
            identifier = f"ip:{request.headers.get('X-Forwarded-For', request.remote_addr) or 'unknown'}"
        return f"{identifier}:{name}"
    except Exception:
        return f"ip:{request.remote_addr or 'unknown'}:{name}"


def rate_limit(limit: int, window: int = 60, name: str | None = None):
    """Token bucket: limit requests per 'window' seconds per user/IP per name."""
    def decorator(fn):
        bucket_name = name or fn.__name__

        @wraps(fn)
        def wrapper(*args, **kwargs):
            now = time.time()
            key = _rate_key(bucket_name)
            with _RATE_LOCK:
                bucket = _RATE_BUCKETS.get(key)
                if not bucket:
                    # tokens, last_refill
                    bucket = [float(limit), now]
                # Refill
                tokens, last = bucket
                elapsed = max(0.0, now - last)
                rate_per_sec = float(limit) / float(window)
                tokens = min(float(limit), tokens + elapsed * rate_per_sec)
                allowed = tokens >= 1.0
                if allowed:
                    tokens -= 1.0
                # Save state
                _RATE_BUCKETS[key] = [tokens, now]
                # Compute remaining and reset secs
                remaining = int(tokens)
                reset = window - int(elapsed) if elapsed <= window else 0

            if not allowed:
                # Too Many Requests
                retry_after = max(1, reset)
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in (request.headers.get('Accept') or ''):
                    resp = jsonify(success=False, message='Too many requests, slow down.')
                else:
                    flash('Too many requests, please slow down.', 'error')
                    resp = redirect(request.referrer or url_for('dashboard', _external=True))
                try:
                    resp.status_code = 429
                except Exception:
                    pass
                try:
                    # Attach standard rate limit headers
                    resp.headers['Retry-After'] = str(retry_after)
                    resp.headers['X-RateLimit-Limit'] = str(limit)
                    resp.headers['X-RateLimit-Remaining'] = str(remaining)
                    resp.headers['X-RateLimit-Reset'] = str(retry_after)
                except Exception:
                    pass
                return resp

            # Proceed and attach headers on successful response
            response = fn(*args, **kwargs)
            try:
                response.headers['X-RateLimit-Limit'] = str(limit)
                response.headers['X-RateLimit-Remaining'] = str(remaining)
                response.headers['X-RateLimit-Reset'] = str(reset)
            except Exception:
                pass
            return response

        return wrapper
    return decorator

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100))
    unit = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST_TIMEZONE))
    is_hod = db.Column(db.Boolean, default=False)  # Field to identify HODs


class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    mobile = db.Column(db.String(20), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    id_proof_path = db.Column(db.String(200))
    id_proof_type = db.Column(db.String(50))  # New column for type of ID proof
    other_id_proof_type = db.Column(db.String(100))  # New column for custom ID proof type if 'Others' is selected
    visitor_image = db.Column(db.String(200))  # New column for visitor's captured photo
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, exited
    approved_at = db.Column(db.DateTime) # New column to store approval timestamp
    check_in_time = db.Column(db.DateTime) # Removed default=datetime.utcnow, as check-in is a separate action
    check_out_time = db.Column(db.DateTime)
    qr_code = db.Column(db.String(200))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    unit = db.Column(db.String(100)) # New column for visitor's unit
    
    # New field for work permit certificate (for vendor services)
    work_permit_certificate = db.Column(db.String(200))  # Path to work permit certificate file
    
    # Field to track who approved the visitor
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # ID of user who approved

    # New fields for Meeting Description
    meeting_id = db.Column(db.String(50))
    requested_by = db.Column(db.String(100))
    no_of_hours = db.Column(db.Integer)
    visit_location = db.Column(db.String(100))

    # New fields for Visitor Details
    visitor_type = db.Column(db.String(50))
    company = db.Column(db.String(100))
    from_datetime = db.Column(db.DateTime)
    to_datetime = db.Column(db.DateTime)
    card_identification_name = db.Column(db.String(100))
    access_group_name = db.Column(db.String(100))
    Visitor_ID = db.Column(db.String(100))
    original_visitor_id = db.Column(db.String(100))

    # New fields for Material Details (single entry for now)
    host = db.relationship('User', foreign_keys=[host_id])
    created_by_user = db.relationship('User', foreign_keys=[created_by])
    approved_by_user = db.relationship('User', foreign_keys=[approved_by_id])
    materials = db.relationship('Material', backref='visitor', lazy=True, cascade="all, delete-orphan")


class Material(db.Model):
    __tablename__ = 'material'
    id = db.Column(db.Integer, primary_key=True)
    visitor_id = db.Column(db.Integer, db.ForeignKey('visitor.id'), nullable=False)
    visitor_code = db.Column(db.String(100), nullable=False)  # 5-digit Visitor_ID
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100))
    make = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))


class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(IST_TIMEZONE), onupdate=lambda: datetime.now(IST_TIMEZONE))

    def __repr__(self):
        return f"<SystemSetting {self.key}: {self.value}>"

def load_settings_from_db():
    with app.app_context():
        settings = SystemSetting.query.all()
        for setting in settings:
            if setting.key in ['MAIL_PORT', 'MAIL_USE_TLS']:
                # Convert to appropriate type if necessary
                if setting.key == 'MAIL_PORT':
                    app.config[setting.key] = int(setting.value)
                elif setting.key == 'MAIL_USE_TLS':
                    app.config[setting.key] = (setting.value == '1')
            else:
                app.config[setting.key] = setting.value
        logging.info("Settings loaded from database into app.config")

# Call this function after db and app are initialized
# with app.app_context():
#     load_settings_from_db()

def get_setting(key, default=None):
    setting = SystemSetting.query.filter_by(key=key).first()
    return setting.value if setting else default


def set_setting(key, value):
    setting = SystemSetting.query.filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        setting = SystemSetting(key=key, value=value)
        db.session.add(setting)
    db.session.commit()

def send_email_background(to_email, subject, body, html_body=None, embedded_image_path=None, embedded_image_cid=None, visitor=None):
    """Internal function to send email in the background"""
    # Check if email functionality is enabled
    if not app.config.get('ENABLE_EMAIL', True):
        logging.info(f"Email sending is disabled. Skipping email to {to_email}.")
        return True

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = to_email

    if html_body:
        msg.set_content(body)
        msg.add_alternative(html_body, subtype='html')
    else:
        msg.set_content(body)

    # Attach embedded image
    if embedded_image_path and os.path.exists(embedded_image_path):
        logging.info(f"Attaching embedded image: {embedded_image_path}")
        with open(embedded_image_path, 'rb') as img_file:
            img_data = img_file.read()
        
        # Ensure Content-ID is always wrapped in angle brackets
        final_cid = f"<{embedded_image_cid.strip('<>')}>" if embedded_image_cid else "<embedded_image>"
        logging.info(f"Using Content-ID: {final_cid}")
        
        mime_image = MIMEImage(img_data, name=os.path.basename(embedded_image_path))
        mime_image.add_header('Content-ID', final_cid)
        mime_image.add_header('Content-Disposition', 'inline', filename=os.path.basename(embedded_image_path))
        msg.add_attachment(mime_image)
        logging.info(f"Image attached successfully")
    elif embedded_image_path:
        logging.warning(f"Embedded image path provided but file does not exist: {embedded_image_path}")

    smtp = None # Initialize smtp to None
    try:
        logging.info(f"Attempting to send email to {to_email}")
        if app.config.get('MAIL_USE_SSL'):
            smtp = smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'], timeout=30)
        else:
            smtp = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'], timeout=30)
            smtp.ehlo()
            if app.config.get('MAIL_USE_TLS'):
                smtp.starttls()
        smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        smtp.send_message(msg)
        logging.info(f"Email sent to {to_email} successfully!")
        return True
    except smtplib.SMTPAuthenticationError as e:
        error_message = f"SMTP Authentication Error: {e}. Please check MAIL_USERNAME and MAIL_PASSWORD in .env. If MFA is enabled, use an App Password."
        logging.error(f"Failed to send email to {to_email}: {error_message}")
        return False
    except smtplib.SMTPConnectError as e:
        error_message = f"SMTP Connection Error: {e}. Please check MAIL_SERVER and MAIL_PORT in .env, and ensure the server is reachable."
        logging.error(f"Failed to send email to {to_email}: {error_message}")
        return False
    except smtplib.SMTPException as e:
        error_message = f"SMTP Error: {e}. A general SMTP error occurred."
        logging.error(f"Failed to send email to {to_email}: {error_message}")
        return False
    except Exception as e:
        error_message = f"An unexpected error occurred: {e}."
        logging.error(f"Failed to send email to {to_email}: {error_message}")
        return False
    finally:
        if smtp:
            try:
                smtp.quit()
            except Exception as e:
                logging.error(f"Failed to close SMTP connection: {e}")

def send_email(to_email, subject, body, html_body=None, embedded_image_path=None, embedded_image_cid=None, visitor=None, async_mode=True):
    """Send email, optionally in async mode to not block the request"""
    # Check if email functionality is enabled
    if not app.config.get('ENABLE_EMAIL', True):
        logging.info(f"Email sending is disabled. Skipping email to {to_email}.")
        return True
    
    if async_mode:
        # Send email in background thread to not block the request
        thread = Thread(target=send_email_background, args=(to_email, subject, body, html_body, embedded_image_path, embedded_image_cid, visitor))
        thread.daemon = True  # Dies when main thread dies
        thread.start()
        logging.info(f"Email to {to_email} queued for sending in background")
        return True  # Return immediately as email is queued
    else:
        # Send email synchronously (old behavior)
        return send_email_background(to_email, subject, body, html_body, embedded_image_path, embedded_image_cid, visitor)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def adjust_script_root():
    # This tells Flask that it's being served under /cms
    if request.path.startswith('/vms'):
        request.environ['SCRIPT_NAME'] = '/vms'


@app.after_request
def set_security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Cache-Control', 'no-store')
    csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; font-src 'self' https://cdnjs.cloudflare.com;"
    response.headers.setdefault('Content-Security-Policy', csp)
    if request.is_secure:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
    return response


def _generate_captcha_text(length=6):
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


@app.route('/vms/captcha')
@rate_limit(limit=60, window=60, name='captcha')
def captcha_image():
    # Generate captcha text and store with TTL
    text = _generate_captcha_text(6)
    session['captcha_text'] = text
    session['captcha_exp'] = time.time() + 120  # 2 minutes

    # Create a moderately sized, normal-font image
    width, height = 180, 60
    bg_color = (245, 248, 250)  # very light gray-blue
    img = Image.new('RGB', (width, height), color=bg_color)
    draw = ImageDraw.Draw(img)

    # Prefer regular (non-bold) fonts; fall back to default
    font = None
    for fname in ['DejaVuSans.ttf', 'Arial.ttf', 'arial.ttf', 'LiberationSans-Regular.ttf', 'LiberationSansNarrow-Regular.ttf']:
        try:
            font = ImageFont.truetype(fname, 32)
            break
        except Exception:
            continue
    if font is None:
        font = ImageFont.load_default()

    # Compute centered position
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
        tw, th = (bbox[2] - bbox[0], bbox[3] - bbox[1])
    except Exception:
        tw, th = draw.textsize(text, font=font)
    x = (width - tw) // 2
    y = (height - th) // 2

    # Minimal background noise (single faint line)
    for _ in range(1):
        draw.line(
            (
                secrets.randbelow(width), secrets.randbelow(height),
                secrets.randbelow(width), secrets.randbelow(height)
            ),
            fill=(200, 210, 220), width=2
        )

    # Draw main text in normal weight
    main_color = (26, 54, 93)  # deep blue
    draw.text((x, y), text, font=font, fill=main_color)

    # Clean border
    draw.rectangle([(0, 0), (width - 1, height - 1)], outline=(180, 190, 200), width=1)

    # Return as PNG
    bio = io.BytesIO()
    img.save(bio, format='PNG')
    bio.seek(0)
    return send_file(bio, mimetype='image/png')


@app.route('/vms/verify_otp', methods=['GET', 'POST'])
@rate_limit(limit=10, window=60, name='verify_otp')
def verify_otp():
    # If OTP is disabled, this route should not be accessible
    if not app.config.get('ENABLE_OTP', True):
        flash('OTP verification is disabled.', 'info')
        return redirect(url_for('login', _external=True))
        
    if request.method == 'POST':
        code = request.form.get('otp', '').strip()
        uid = session.get('mfa_user_id')
        otp = session.get('mfa_otp')
        exp = session.get('mfa_otp_exp')
        uname = session.get('mfa_username')
        if not (uid and otp and exp and time.time() <= float(exp)):
            flash('OTP expired or missing. Please login again.', 'error')
            return redirect(url_for('login', _external=True))
        if code != str(otp):
            flash('Invalid OTP. Try again.', 'error')
            return render_template('mfa_verify.html')

        # OTP success; log the user in
        user = User.query.get(int(uid))
        if not user:
            flash('User not found. Please login again.', 'error')
            return redirect(url_for('login', _external=True))
        try:
            session.pop('mfa_user_id', None)
            session.pop('mfa_username', None)
            session.pop('mfa_otp', None)
            session.pop('mfa_otp_exp', None)
        except Exception:
            pass
        login_user(user)
        # Mark login attempts success
        _record_attempt(uname or user.username, success=True)
        flash('Login successful!', 'success')
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard', _external=True))
        return redirect(url_for('dashboard', _external=True))

    return render_template('mfa_verify.html')


@app.route('/vms/resend_otp', methods=['POST'])
@rate_limit(limit=5, window=300, name='resend_otp')
def resend_otp():
    # If OTP is disabled, this function should not be used
    if not app.config.get('ENABLE_OTP', True):
        flash('OTP functionality is disabled.', 'info')
        return redirect(url_for('login', _external=True))
        
    uid = session.get('mfa_user_id')
    if not uid:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login', _external=True))
    user = User.query.get(int(uid))
    if not user or not user.email:
        flash('Unable to resend OTP. Please login again.', 'error')
        return redirect(url_for('login', _external=True))
    otp = f"{secrets.randbelow(1000000):06d}"
    session['mfa_otp'] = otp
    session['mfa_otp_exp'] = time.time() + 300
    
    # Skip email sending if disabled
    if not app.config.get('ENABLE_EMAIL', True):
        flash('A new OTP has been sent to your email.', 'info')
        return redirect(url_for('verify_otp', _external=True))
        
    try:
        subject = 'Your VMS Login OTP'
        body = f"Your one-time password is: {session['mfa_otp']}\nIt expires in 5 minutes."
        html_body = f"<p>Your one-time password is:</p><h2 style='letter-spacing:3px;'>{otp}</h2><p>This code expires in 5 minutes.</p>"
        send_email(user.email, subject, body, html_body=html_body, async_mode=True)
        flash('A new OTP has been sent to your email.', 'info')
    except Exception:
        flash('Failed to resend OTP. Please try again.', 'error')
    return redirect(url_for('verify_otp', _external=True))


@app.route('/vms/login', methods=['GET', 'POST'])
@rate_limit(limit=10, window=60, name='login')
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        captcha_input = request.form.get('captcha', '').strip()
        user = User.query.filter_by(email=email).first()
        if user and _is_locked(email):
            flash('Too many failed attempts. Please try again later.', 'error')
            return render_template('login.html')

        # Validate captcha from session (if enabled)
        if app.config.get('ENABLE_CAPTCHA', True):
            captcha_text = session.get('captcha_text')
            captcha_exp = session.get('captcha_exp')
            if not captcha_text or not captcha_exp or time.time() > float(captcha_exp):
                flash('Captcha expired. Please reload the captcha.', 'error')
                return render_template('login.html')
            if captcha_input.lower() != str(captcha_text).lower():
                flash('Invalid captcha. Try again.', 'error')
                return render_template('login.html')

        logging.info(f"Login attempt - email: {email}")

        if user and check_password_hash(user.password_hash, password):
            logging.info("Password check successful; initiating MFA OTP")
            # Do not clear session entirely (will lose CSRF); selectively reset captcha
            # Only pop captcha session variables if CAPTCHA is enabled
            if app.config.get('ENABLE_CAPTCHA', True):
                session.pop('captcha_text', None)
                session.pop('captcha_exp', None)

            # Skip OTP verification if disabled
            if not app.config.get('ENABLE_OTP', True):
                # Log the user in directly
                login_user(user)
                _record_attempt(email, success=True)
                flash('Login successful!', 'success')
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard', _external=True))
                return redirect(url_for('dashboard', _external=True))

            # Generate OTP and store in session
            otp = f"{secrets.randbelow(1000000):06d}"
            session['mfa_user_id'] = user.id
            session['mfa_username'] = user.username  # Store username for logging/display if needed
            session['mfa_otp'] = otp
            session['mfa_otp_exp'] = time.time() + 300  # 5 minutes

# The following code is disabled to enforce OTP verification.
            try:
                subject = 'Your VMS Login OTP'
                body = f"Your one-time password is: {session['mfa_otp']}\nIt expires in 5 minutes."
                html_body = f"<p>Your one-time password is:</p><h2 style='letter-spacing:3px;'>{session['mfa_otp']}</h2><p>This code expires in 5 minutes.</p>"
                send_email(user.email, subject, body, html_body=html_body, async_mode=True)
                flash('OTP sent to your email address.', 'info')
            except Exception:
                flash('Failed to send OTP. Please try again.', 'error')
                return render_template('login.html')

            return redirect(url_for('verify_otp', _external=True))

        else:
            logging.info("Invalid credentials")
            _record_attempt(email, success=False)
            flash('Invalid credentials!', 'error')

    return render_template('login.html')

@app.route('/vms/forgot_password', methods=['GET', 'POST'])
# The following code is disabled to enforce OTP verification.
@rate_limit(limit=5, window=300, name='forgot_password')
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No account found with that email address.', 'error')
            return render_template('forgot_password.html')

        # Generate OTP and store in session
        otp = f"{secrets.randbelow(1000000):06d}"
        session['reset_user_id'] = user.id
        session['reset_otp'] = otp
        session['reset_otp_exp'] = time.time() + 600  # 10 minutes expiration

        # Skip email sending if disabled
        if not app.config.get('ENABLE_EMAIL', True):
            flash('A password reset OTP has been sent to your email address.', 'info')
            return redirect(url_for('verify_reset_otp', _external=True))

        try:
            subject = 'VMS Password Reset OTP'
            body = f"Your one-time password for password reset is: {otp}\nIt expires in 10 minutes."
            html_body = f"<p>Your one-time password for password reset is:</p><h2 style='letter-spacing:3px;'>{otp}</h2><p>This code expires in 10 minutes.</p>"
            send_email(user.email, subject, body, html_body=html_body, async_mode=True)
            flash('A password reset OTP has been sent to your email address.', 'info')
            return redirect(url_for('verify_reset_otp', _external=True))
        except Exception as e:
            logging.error(f"Error sending password reset OTP to {user.email}: {e}")
            flash('Failed to send OTP. Please try again.', 'error')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@app.route('/vms/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login',_external=True))

@app.route('/vms/verify_reset_otp', methods=['GET', 'POST'])
@rate_limit(limit=10, window=60, name='verify_reset_otp')
def verify_reset_otp():
    # If OTP is disabled, this route should not be accessible
    if not app.config.get('ENABLE_OTP', True):
        flash('OTP verification is disabled.', 'info')
        return redirect(url_for('login', _external=True))
        
    if request.method == 'POST':
        code = request.form.get('otp', '').strip()
        uid = session.get('reset_user_id')
        otp = session.get('reset_otp')
        exp = session.get('reset_otp_exp')

        if not (uid and otp and exp and time.time() <= float(exp)):
            flash('OTP expired or missing. Please restart the password reset process.', 'error')
            return redirect(url_for('forgot_password', _external=True))

        if code != str(otp):
            flash('Invalid OTP. Try again.', 'error')
            return render_template('verify_reset_otp.html')

        # OTP is valid, allow user to reset password
        session['otp_verified_user_id'] = uid
        session.pop('reset_user_id', None)
        session.pop('reset_otp', None)
        session.pop('reset_otp_exp', None)
        flash('OTP verified. You can now reset your password.', 'success')
        return redirect(url_for('reset_password', _external=True))

    return render_template('verify_reset_otp.html')

@app.route('/vms/resend_reset_otp', methods=['POST'])
@rate_limit(limit=3, window=300, name='resend_reset_otp')
def resend_reset_otp():
    uid = session.get('reset_user_id')
    if not uid:
        flash('Session expired. Please restart the password reset process.', 'error')
        return redirect(url_for('forgot_password', _external=True))
    
    user = User.query.get(int(uid))
    if not user or not user.email:
        flash('Unable to resend OTP. Please restart the password reset process.', 'error')
        return redirect(url_for('forgot_password', _external=True))
        
    otp = f"{secrets.randbelow(1000000):06d}"
    session['reset_otp'] = otp
    session['reset_otp_exp'] = time.time() + 600  # 10 minutes expiration
    
    # Skip email sending if disabled
    if not app.config.get('ENABLE_EMAIL', True):
        flash('A new password reset OTP has been sent to your email.', 'info')
        return redirect(url_for('verify_reset_otp', _external=True))

    try:
        subject = 'VMS Password Reset OTP'
        body = f"Your new one-time password for password reset is: {otp}\nIt expires in 10 minutes."
        html_body = f"<p>Your new one-time password for password reset is:</p><h2 style='letter-spacing:3px;'>{otp}</h2><p>This code expires in 10 minutes.</p>"
        send_email(user.email, subject, body, html_body=html_body, async_mode=True)
        flash('A new password reset OTP has been sent to your email.', 'info')
    except Exception as e:
        logging.error(f"Error resending password reset OTP to {user.email}: {e}")
        flash('Failed to resend OTP. Please try again.', 'error')
    
    return redirect(url_for('verify_reset_otp', _external=True))

@app.route('/vms/reset_password', methods=['GET', 'POST'])
@rate_limit(limit=5, window=300, name='reset_password')
def reset_password():
    uid = session.get('otp_verified_user_id')
    if not uid:
        flash('Password reset session expired or invalid. Please restart the process.', 'error')
        return redirect(url_for('forgot_password', _external=True))

    user = User.query.get(int(uid))
    if not user:
        flash('User not found. Please restart the password reset process.', 'error')
        return redirect(url_for('forgot_password', _external=True))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Please enter and confirm your new password.', 'error')
            return render_template('reset_password.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')

        # Password policy: min 8 chars, upper, lower, digit, special
        policy = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$')
        if not policy.match(new_password):
            flash('Password must be at least 8 characters and include upper, lower, digit, and special character.', 'error')
            return render_template('reset_password.html')

        user.password_hash = generate_password_hash(new_password, method='scrypt:32768:8:1')
        db.session.commit()

        session.pop('otp_verified_user_id', None) # Clear the session variable after successful reset
        flash('Your password has been reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login', _external=True))

    return render_template('reset_password.html')
    otp = f"{secrets.randbelow(1000000):06d}"
    session['reset_otp'] = otp
    session['reset_otp_exp'] = time.time() + 600  # 10 minutes expiration

    try:
        subject = 'VMS Password Reset OTP'
        body = f"Your new one-time password for password reset is: {otp}\nIt expires in 10 minutes."
        html_body = f"<p>Your new one-time password for password reset is:</p><h2 style='letter-spacing:3px;'>{otp}</h2><p>This code expires in 10 minutes.</p>"
        send_email(user.email, subject, body, html_body=html_body, async_mode=True)
        flash('A new password reset OTP has been sent to your email.', 'info')
    except Exception as e:
        logging.error(f"Error resending password reset OTP to {user.email}: {e}")
        flash('Failed to resend OTP. Please try again.', 'error')
    
    return redirect(url_for('verify_reset_otp', _external=True))

@app.route('/vms/dashboard')
@login_required
def dashboard():
    today = datetime.now().date()

    # Get statistics based on user role
    if current_user.role == 'admin':
        today_visitors = Visitor.query.filter(
            db.func.date(Visitor.check_in_time) == today
        ).count()

        pending_approvals = Visitor.query.filter_by(status='pending').count()

        total_exits = Visitor.query.filter(
            Visitor.status == 'exited',
            db.func.date(Visitor.check_out_time) == today
        ).count()

        recent_visitors = Visitor.query.filter(
            db.func.date(Visitor.from_datetime) == today
        ).order_by(Visitor.from_datetime.desc()).limit(5).all()
    elif current_user.role == 'security':
        today_visitors = Visitor.query.filter(
            db.or_(
                db.func.date(Visitor.check_in_time) == today,
                db.and_(
                    db.func.date(Visitor.from_datetime) == today,
                    Visitor.status == 'pending'
                )
            ),
            Visitor.unit == current_user.unit
        ).count()

        pending_approvals = Visitor.query.filter_by(
            status='pending',
            unit=current_user.unit
        ).count()

        total_exits = Visitor.query.filter(
            Visitor.status == 'exited',
            db.func.date(Visitor.check_out_time) == today,
            Visitor.unit == current_user.unit
        ).count()

        recent_visitors = Visitor.query.filter(
            db.func.date(Visitor.from_datetime) == today,
            Visitor.unit == current_user.unit
        ).order_by(Visitor.from_datetime.desc()).limit(5).all()

    elif current_user.is_hod and current_user.department:
        # HODs see statistics for all employees in their department
        today_visitors = Visitor.query.join(User, Visitor.host_id == User.id).filter(
            db.or_(
                db.func.date(Visitor.check_in_time) == today,
                db.and_(
                    db.func.date(Visitor.from_datetime) == today,
                    Visitor.status == 'pending'
                )
            ),
            User.department == current_user.department
        ).count()

        pending_approvals = Visitor.query.join(User, Visitor.host_id == User.id).filter(
            Visitor.status == 'pending',
            User.department == current_user.department
        ).count()

        total_exits = Visitor.query.join(User, Visitor.host_id == User.id).filter(
            Visitor.status == 'exited',
            User.department == current_user.department,
            db.func.date(Visitor.check_out_time) == today
        ).count()

        recent_visitors = Visitor.query.join(User, Visitor.host_id == User.id).filter(
            db.func.date(Visitor.from_datetime) == today,
            User.department == current_user.department
        ).order_by(Visitor.from_datetime.desc()).limit(5).all()
    else:  # Regular employee
        today_visitors = Visitor.query.filter(
            db.or_(
                db.func.date(Visitor.check_in_time) == today,
                db.and_(
                    db.func.date(Visitor.from_datetime) == today,
                    Visitor.status == 'pending'
                )
            ),
            Visitor.host_id == current_user.id
        ).count()

        pending_approvals = Visitor.query.filter_by(
            status='pending'
        ).filter(
            Visitor.host_id == current_user.id
        ).count()

        total_exits = Visitor.query.filter(
            Visitor.status == 'exited',
            Visitor.host_id == current_user.id,
            db.func.date(Visitor.check_out_time) == today
        ).count()

        recent_visitors = Visitor.query.filter(
            db.func.date(Visitor.from_datetime) == today,
            Visitor.host_id == current_user.id
        ).order_by(Visitor.from_datetime.desc()).limit(5).all()

    # Calculate total hours visited for each visitor
    for visitor in recent_visitors:
        if visitor.check_in_time and visitor.check_out_time:
            time_difference = visitor.check_out_time - visitor.check_in_time
            hours, remainder = divmod(time_difference.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            visitor.total_hours_visited = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        else:
            visitor.total_hours_visited = "N/A"

    approved_visitors = Visitor.query.filter_by(status='approved').count()
    rejected_visitors = Visitor.query.filter_by(status='rejected').count()
    exited_visitors = Visitor.query.filter_by(status='exited').count()

    return render_template('dashboard.html',
                           today_visitors=today_visitors,
                           pending_approvals=pending_approvals,
                           total_exits=total_exits,
                           recent_visitors=recent_visitors,
                           approved_visitors=approved_visitors,
                           rejected_visitors=rejected_visitors,
                           exited_visitors=exited_visitors)


@app.route('/vms/vms_master_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    # Statistics
    total_users = User.query.count()
    total_visitors = Visitor.query.count()
    today = datetime.now().date()
    today_visitors = Visitor.query.filter(db.func.date(Visitor.check_in_time) == today).count()
    pending_approvals = Visitor.query.filter_by(status='pending').count()
    
    # New: Fetch counts for Approved, Rejected, Exited visitors
    approved_visitors_count = Visitor.query.filter_by(status='approved').count()
    rejected_visitors_count = Visitor.query.filter_by(status='rejected').count()
    exited_visitors_count = Visitor.query.filter_by(status='exited').count()

    # Fetch recent visitors for today, including those registered today with 'pending' status
    today = datetime.now(IST_TIMEZONE).date()
    recent_visitors = Visitor.query.filter(
        db.func.date(Visitor.from_datetime) == today
    ).order_by(Visitor.from_datetime.desc()).limit(5).all()

    # Calculate total hours visited for each visitor
    for visitor in recent_visitors:
        if visitor.check_in_time and visitor.check_out_time:
            time_difference = visitor.check_out_time - visitor.check_in_time
            hours, remainder = divmod(time_difference.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            visitor.total_hours_visited = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        else:
            visitor.total_hours_visited = "N/A"

    return render_template('admin_dashboard.html',
                           total_users=total_users,
                           total_visitors=total_visitors,
                           today_visitors=today_visitors,
                           pending_approvals=pending_approvals,
                           approved_visitors_count=approved_visitors_count,
                           rejected_visitors_count=rejected_visitors_count,
                           exited_visitors_count=exited_visitors_count,
                           recent_visitors=recent_visitors)

@app.route('/vms/approval_dashboard')
@login_required
def approval_dashboard():
    if current_user.role not in ['admin', 'security', 'employee']:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    # Get pending approvals based on user role
    if current_user.role == 'admin':
        pending_approvals = Visitor.query.filter_by(status='pending').order_by(Visitor.check_in_time.desc()).all()
    elif current_user.role == 'security':
        pending_approvals = Visitor.query.filter_by(status='pending', unit=current_user.unit).order_by(Visitor.check_in_time.desc()).all()
    elif current_user.is_hod and current_user.department:
        # HODs see pending approvals for all employees in their department
        pending_approvals = Visitor.query.join(User, Visitor.host_id == User.id).filter(
            Visitor.status == 'pending',
            User.department == current_user.department
        ).order_by(Visitor.check_in_time.desc()).all()
    else:  # Regular employee
        pending_approvals = Visitor.query.filter_by(status='pending', host_id=current_user.id).order_by(Visitor.check_in_time.desc()).all()

    return render_template('approval_dashboard.html', pending_approvals=pending_approvals)

@app.route('/vms/get_visitor_details/<string:visitor_id>')
@rate_limit(limit=60, window=60, name='get_visitor_details')
@login_required
def get_visitor_details(visitor_id):
    try:
        # Log the raw visitor_id received
        logging.info(f"Raw visitor_id received: '{visitor_id}'")
        
        # Try to find visitor by original ID first, then by cleaned ID
        visitor = Visitor.query.filter(
            db.or_(
                Visitor.Visitor_ID == visitor_id,
                Visitor.original_visitor_id == visitor_id
            )
        ).options(
            joinedload(Visitor.host),
            joinedload(Visitor.materials),
            joinedload(Visitor.created_by_user),
            joinedload(Visitor.approved_by_user)
        ).first()
        
        # If not found, try with cleaned ID (digits only)
        if not visitor:
            cleaned_visitor_id = re.sub(r'\D', '', visitor_id)
            logging.info(f"Visitor not found with raw ID, trying cleaned_visitor_id: '{cleaned_visitor_id}'")
            
            if cleaned_visitor_id:
                visitor = Visitor.query.filter(Visitor.Visitor_ID == cleaned_visitor_id).options(
                    joinedload(Visitor.host),
                    joinedload(Visitor.materials),
                    joinedload(Visitor.created_by_user),
                    joinedload(Visitor.approved_by_user)
                ).first()
        
        if not visitor:
            logging.warning(f"Visitor with ID '{visitor_id}' not found in database.")
            # Check if this is an AJAX request or direct browser access
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.accept_json:
                return jsonify(success=False, message='Visitor not found!'), 404
            else:
                flash('Visitor not found!', 'error')
                return redirect(url_for('visitor_status',_external=True))

        logging.info(f"Visitor found: {visitor.name} (ID: {visitor.id}, Visitor_ID: {visitor.Visitor_ID})")
        
        # Log warnings for missing related objects
        if not visitor.host:
            logging.warning(f"Visitor {visitor.id} has no associated host (host_id: {visitor.host_id}).")
        if not visitor.created_by_user:
            logging.warning(f"Visitor {visitor.id} has no associated creator (created_by: {visitor.created_by}).")
        if not visitor.materials:
            logging.info(f"Visitor {visitor.id} has no associated materials.")

        qr_code_url = url_for('display_qr_code', visitor_id=visitor.Visitor_ID)
        
        # Check if this is an AJAX request (wants JSON) or browser request (wants HTML)
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
                  'application/json' in request.headers.get('Accept', '')
        
        # Authorization: admin; security only for same unit; employee only if host
        if not (
            (current_user.role == 'admin') or
            (current_user.role == 'security' and getattr(visitor, 'unit', None) == current_user.unit) or
            (current_user.role == 'employee' and visitor.host_id == current_user.id)
        ):
            logging.warning('Unauthorized access attempt to visitor details.')
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
                return jsonify(success=False, message='Access denied!'), 403
            flash('Access denied!', 'error')
            return redirect(url_for('dashboard',_external=True))

        if is_ajax:
            # Return JSON for AJAX requests (from check-in/check-out pages)
            try:
                materials_data = [{
                    'name': m.name,
                    'type': m.type,
                    'make': m.make,
                    'serial_number': m.serial_number
                } for m in visitor.materials]

                visitor_data = {
                    'id': visitor.id,
                    'name': visitor.name,
                    'email': visitor.email,
                    'mobile': visitor.mobile,
                    'purpose': visitor.purpose,
                    'host_name': visitor.host.username if visitor.host else 'N/A',
                    'status': visitor.status,
                    'check_in_time': visitor.check_in_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_in_time else 'N/A',
                    'check_out_time': visitor.check_out_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_out_time else 'N/A',
                    'visitor_type': visitor.visitor_type,
                    'company': visitor.company,
                    'from_datetime': visitor.from_datetime.strftime('%Y-%m-%d %H:%M') if visitor.from_datetime else 'N/A',
                    'to_datetime': visitor.to_datetime.strftime('%Y-%m-%d %H:%M') if visitor.to_datetime else 'N/A',
                    'card_identification_name': visitor.card_identification_name,
                    'access_group_name': visitor.access_group_name,
                    'Visitor_ID': visitor.Visitor_ID,
                    'unit': visitor.unit,
                    'meeting_id': visitor.meeting_id,
                    'requested_by': visitor.requested_by,
                    'no_of_hours': visitor.no_of_hours,
                    'visit_location': visitor.visit_location,
                    'id_proof_type': visitor.id_proof_type,
                    'other_id_proof_type': visitor.other_id_proof_type,
                    'id_proof_path': visitor.id_proof_path,
                    'visitor_image': visitor.visitor_image if visitor.visitor_image else None,
                    'work_permit_certificate': visitor.work_permit_certificate,
                    'approved_by': visitor.approved_by_user.username if visitor.approved_by_user else 'N/A',
                    'qr_code_url': qr_code_url,
                    'materials': materials_data
                }
                return jsonify(visitor_data), 200
            except Exception as json_error:
                logging.error(f"Error creating JSON response: {json_error}", exc_info=True)
                return jsonify(success=False, message=f'Internal server error: {json_error}'), 500
        else:
            # Return HTML for direct browser access
            return render_template('visitor_details.html', visitor=visitor, qr_code_url=qr_code_url)

    except Exception as e:
        logging.error(f"Error getting visitor details for Visitor_ID {visitor_id}: {e}", exc_info=True)
        # Check if AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
            return jsonify(success=False, message='Internal server error while fetching visitor details.'), 500
        else:
            flash('Error fetching visitor details.', 'error')
            return redirect(url_for('visitor_status', _external=True))

@app.route('/vms/visitor_status', methods=['GET', 'POST'])
@rate_limit(limit=60, window=60, name='visitor_status')
@login_required
def visitor_status():
    if current_user.role not in ['admin', 'security', 'employee']:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    start_date_str = request.form.get('start_date')
    end_date_str = request.form.get('end_date')

    query = Visitor.query

    if current_user.role == 'security':
        query = query.filter_by(unit=current_user.unit)
    elif current_user.role == 'employee':
        query = query.filter_by(host_id=current_user.id)

    if start_date_str and end_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        # Add one day to end_date to include the entire end_date
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
        visitors = query.filter(Visitor.check_in_time >= start_date, Visitor.check_in_time < end_date).all()
    else:
        # If no dates are provided, fetch all visitors
        visitors = query.all()

    return render_template('visitor_status.html', visitors=visitors, start_date=start_date_str, end_date=end_date_str)


@app.route('/vms/export_visitors_csv')
@rate_limit(limit=10, window=60, name='export_csv')
@login_required
def export_visitors_csv():
    if current_user.role not in ['admin', 'security', 'employee']:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    query = Visitor.query

    if current_user.role == 'security':
        query = query.filter_by(unit=current_user.unit)
    elif current_user.role == 'employee':
        query = query.filter_by(host_id=current_user.id)

    visitors = query.all()
    output = io.StringIO()
    writer = csv.writer(output)

    # Write headers
    writer.writerow(['Name', 'Visitor ID', 'Mobile', 'Purpose', 'Host', 'Status', 'Check-in Time', 'Check-out Time'])

    # Write data
    for visitor in visitors:
        writer.writerow([
            visitor.name,
            visitor.Visitor_ID,
            visitor.mobile,
            visitor.purpose,
            visitor.host.username if visitor.host else 'N/A',
            visitor.status,
            visitor.check_in_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_in_time else '',
            visitor.check_out_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_out_time else ''
        ])

    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')),
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='visitor_data.csv')

@app.route('/vms/check_in_approval', methods=['GET', 'POST'])
@rate_limit(limit=60, window=60, name='check_in')
@login_required
def check_in_approval():
    if current_user.role not in ['admin', 'security']:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    if request.method == 'POST':
        visitor_id = request.form.get('visitor_id')
        work_permit_file = request.files.get('work_permit_certificate')
        work_permit_captured_image = request.form.get('work_permit_captured_image')  # Captured image from camera
        if visitor_id:
            try:
                visitor = Visitor.query.filter_by(Visitor_ID=visitor_id).first()
                if visitor:
                    if current_user.role == 'security' and visitor.unit != current_user.unit:
                        flash('Access denied to check-in for this unit.', 'error')
                        return redirect(url_for('check_in_approval', _external=True))
                    
                    # Check if purpose is 'Vendor Service' and require work permit certificate
                    if visitor.purpose and 'Vendor Service' in visitor.purpose and not visitor.work_permit_certificate:
                        # If work permit certificate is not provided yet, check if it's being uploaded now
                        if work_permit_file and work_permit_file.filename != '':
                            # Validate file type
                            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
                            if '.' in work_permit_file.filename and \
                               work_permit_file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                                # Generate unique filename
                                filename = f"work_permit_{visitor_id}_{work_permit_file.filename}"
                                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                                work_permit_file.save(filepath)
                                
                                # Update visitor with work permit certificate path
                                visitor.work_permit_certificate = filename
                                db.session.commit()
                                
                                # Check if this is an AJAX request (JSON response needed)
                                if request.headers.get('Content-Type', '').startswith('application/json') or \
                                   request.headers.get('X-Requested-With', '').lower() == 'xmlhttprequest':
                                    return jsonify({'success': True, 'message': 'Work permit certificate uploaded successfully!'})
                                else:
                                    flash('Work permit certificate uploaded successfully!', 'success')
                            else:
                                # Check if this is an AJAX request
                                if request.headers.get('Content-Type', '').startswith('application/json') or \
                                   request.headers.get('X-Requested-With', '').lower() == 'xmlhttprequest':
                                    return jsonify({'success': False, 'message': 'Invalid file type. Only PNG, JPG, JPEG, GIF, and PDF files are allowed for work permit certificate.'})
                                else:
                                    flash('Invalid file type. Only PNG, JPG, JPEG, GIF, and PDF files are allowed for work permit certificate.', 'error')
                                    return redirect(url_for('check_in_approval', _external=True))
                        elif work_permit_captured_image:
                            # Process captured image from camera
                            import base64
                            try:
                                # Extract the image data from the data URL
                                if work_permit_captured_image.startswith('data:image'):
                                    # Extract the image format and data
                                    header, encoded = work_permit_captured_image.split(',', 1)
                                    image_format = header.split('/')[1].split(';')[0]
                                    
                                    # Decode the base64 image data
                                    image_data = base64.b64decode(encoded)
                                    
                                    # Generate a unique filename
                                    filename = f"work_permit_{visitor_id}_{datetime.now(IST_TIMEZONE).strftime('%Y%m%d_%H%M%S')}.jpg"
                                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                                    
                                    # Save the image
                                    with open(filepath, 'wb') as f:
                                        f.write(image_data)
                                    
                                    # Update visitor with work permit certificate path
                                    visitor.work_permit_certificate = filename
                                    db.session.commit()
                                    
                                    # Check if this is an AJAX request (JSON response needed)
                                    if request.headers.get('Content-Type', '').startswith('application/json') or \
                                       request.headers.get('X-Requested-With', '').lower() == 'xmlhttprequest':
                                        return jsonify({'success': True, 'message': 'Work permit certificate uploaded successfully!'})
                                    else:
                                        flash('Work permit certificate uploaded successfully!', 'success')
                                else:
                                    # Check if this is an AJAX request
                                    if request.headers.get('Content-Type', '').startswith('application/json') or \
                                       request.headers.get('X-Requested-With', '').lower() == 'xmlhttprequest':
                                        return jsonify({'success': False, 'message': 'Invalid image format received from camera.'})
                                    else:
                                        flash('Invalid image format received from camera.', 'error')
                                        return redirect(url_for('check_in_approval', _external=True))
                            except Exception as e:
                                logging.error(f"Error processing captured image: {e}")
                                # Check if this is an AJAX request
                                if request.headers.get('Content-Type', '').startswith('application/json') or \
                                   request.headers.get('X-Requested-With', '').lower() == 'xmlhttprequest':
                                    return jsonify({'success': False, 'message': 'Error processing captured image.'})
                                else:
                                    flash('Error processing captured image.', 'error')
                                    return redirect(url_for('check_in_approval', _external=True))
                        else:
                            # Check if this is an AJAX request
                            if request.headers.get('Content-Type', '').startswith('application/json') or \
                               request.headers.get('X-Requested-With', '').lower() == 'xmlhttprequest':
                                return jsonify({'success': False, 'message': 'Work permit certificate required for Vendor Service visitors. Please upload the certificate.'})
                            else:
                                # Show form to upload work permit certificate
                                flash('Work permit certificate required for Vendor Service visitors. Please upload the certificate.', 'error')
                                return render_template('check_in_approval.html', approved_visitors=[visitor])
                    
                    # Only allow check-in if status is 'approved'
                    if visitor.status == 'approved':
                        visitor.check_in_time = datetime.now(IST_TIMEZONE)
                        visitor.status = 'checked-in'  # Update status to checked-in
                        try:
                            db.session.commit()
                            flash(f"{visitor.name} checked in successfully!", 'success')
                            return redirect(url_for('check_in_approval', _external=True))  # Redirect back to the same page to refresh list
                        except Exception as db_error:
                            db.session.rollback()
                            logging.error(f"Database error during check-in: {db_error}")
                            flash(f"Database error during check-in: {db_error}", 'error')
                    else:
                        flash(f"Visitor {visitor.name} (ID: {visitor_id}) is not approved for check-in. Current status: {visitor.status}", 'error')
                else:
                    flash('Invalid Visitor ID!', 'error')
            except Exception as e:
                logging.error(f"Error checking in visitor: {e}", exc_info=True)
                flash(f"Error checking in visitor: {e}", 'error')
        else:
            flash('No Visitor ID received!', 'error')

    search_term = request.args.get('search_term', '').strip()
    query = Visitor.query.filter_by(status='approved')

    if search_term:
        query = query.filter(db.or_(
            Visitor.name.ilike(f"%{search_term}%"),
            Visitor.Visitor_ID == search_term
        ))

    if current_user.role == 'security':
        query = query.filter_by(unit=current_user.unit)

    approved_visitors = query.order_by(Visitor.check_in_time.desc()).all()

    return render_template('check_in_approval.html', approved_visitors=approved_visitors)


@app.route('/vms/check_out_approval', methods=['GET', 'POST'])
@rate_limit(limit=60, window=60, name='check_out')
@login_required
def check_out_approval():
    if current_user.role not in ['admin', 'security']:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    if request.method == 'POST':
        visitor_id = request.form.get('visitor_id')
        if visitor_id:
            try:
                visitor = Visitor.query.filter_by(Visitor_ID=visitor_id).first()
                if visitor:
                    if current_user.role == 'security' and visitor.unit != current_user.unit:
                        flash('Access denied to check-out for this unit.', 'error')
                        return redirect(url_for('check_out_approval',_external=True))
                    # Only allow check-out if status is 'checked-in'
                    if visitor.status == 'checked-in':
                        visitor.check_out_time = datetime.now(IST_TIMEZONE)
                        visitor.status = 'exited' # Update status to exited
                        db.session.commit()
                        flash(f"{visitor.name} checked out successfully!", 'success')
                        return redirect(url_for('check_out_approval',_external=True)) # Redirect back to the same page to refresh list
                    else:
                        flash(f"Visitor {visitor.name} (ID: {visitor_id}) is not checked-in for check-out. Current status: {visitor.status}", 'error')
                else:
                    flash('Invalid Visitor ID!', 'error')
            except Exception as e:
                flash(f"Error checking out visitor: {e}", 'error')
        else:
            flash('No Visitor ID received!', 'error')

    search_term = request.args.get('search_term', '').strip()
    query = Visitor.query.filter_by(status='checked-in')

    if search_term:
        query = query.filter(db.or_(
            Visitor.name.ilike(f"%{search_term}%"),
            Visitor.Visitor_ID == search_term
        ))

    if current_user.role == 'security':
        query = query.filter_by(unit=current_user.unit)

    checked_in_visitors = query.order_by(Visitor.check_in_time.desc()).all()

    return render_template('check_out_approval.html', checked_in_visitors=checked_in_visitors)


@app.route('/vms/user_management')
@login_required
def user_management():
    if current_user.role != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))
    users = User.query.all()
    return render_template('user_management.html', users=users)


@app.route('/vms/register_visitor', methods=['GET', 'POST'])
@rate_limit(limit=20, window=60, name='register_visitor')
@login_required
def register_visitor():
    # Only allow specific roles
    if current_user.role not in ['admin', 'security', 'employee']:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    employees = User.query.filter_by(role='employee', is_active=True).all()

    if request.method == 'GET':
        generated_visitor_id = ''.join(random.choices('0123456789', k=5))
        return render_template('register_visitor.html', employees=employees, generated_visitor_id=generated_visitor_id)

    # POST processing
    try:
        # Debug: Log all form data
        logging.info("="*50)
        logging.info("REGISTER VISITOR FORM SUBMISSION")
        logging.info(f"Form keys: {list(request.form.keys())}")
        logging.info(f"Form values preview: {dict(list(request.form.items())[:10])}")
        logging.info("="*50)
        
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        mobile = request.form.get('mobile', '').strip()
        
        # Handle purpose dropdown and additional fields
        purpose = request.form.get('purpose', '').strip()
        other_purpose = request.form.get('other_purpose', '').strip()
        company_name = request.form.get('company_name', '').strip()
        esi_insurance_no = request.form.get('esi_insurance_no', '').strip()
        
        # Process purpose based on selection
        if purpose == 'Others' and other_purpose.strip():
            purpose = other_purpose.strip()
        elif purpose == 'Others' and (not other_purpose or not other_purpose.strip()):
            flash('Please specify the purpose of visit in the text field when selecting "Others".', 'error')
            return render_template('register_visitor.html', employees=employees)
        elif purpose == 'Vendor Service':
            # For Vendor Service, company name and ESI/Insurance No are required
            if not company_name.strip():
                flash('Company Name is required when selecting "Vendor Service".', 'error')
                return render_template('register_visitor.html', employees=employees)
            if not esi_insurance_no.strip():
                flash('ESI / Insurance No is required when selecting "Vendor Service".', 'error')
                return render_template('register_visitor.html', employees=employees)
            # Update purpose to include company name
            purpose = f"Vendor Service - {company_name}"
        else:
            # For Interview and Meeting, just use the selected value
            pass
        host_id = request.form.get('host_id')
        try:
            host_id = int(host_id) if host_id else None
        except ValueError:
            host_id = None
            
        # Ensure host_id is provided since it's required
        if not host_id:
            flash('Please select a host for the visitor.', 'error')
            return render_template('register_visitor.html', employees=employees)

        id_proof_type = request.form.get('id_proof_type')
        other_id_proof_type_value = request.form.get('other_id_proof_type')
        
        # Validate ID proof fields are mandatory
        if not id_proof_type:
            flash('ID Proof Type is required.', 'error')
            return render_template('register_visitor.html', employees=employees)
        
        final_id_proof_type = other_id_proof_type_value if id_proof_type == 'Others' else id_proof_type

        # Meeting fields
        meeting_id = request.form.get('meeting_id')
        requested_by = request.form.get('requested_by')
        no_of_hours = request.form.get('no_of_hours', type=int)
        visit_location = request.form.get('visit_location')

        # Visitor details
        visitor_type = request.form.get('visitor_type')
        from_datetime_str = request.form.get('from_datetime')
        to_datetime_str = request.form.get('to_datetime')
        from_datetime = datetime.strptime(from_datetime_str, '%Y-%m-%dT%H:%M') if from_datetime_str else datetime.now(IST_TIMEZONE)
        to_datetime = datetime.strptime(to_datetime_str, '%Y-%m-%dT%H:%M') if to_datetime_str else datetime.now(IST_TIMEZONE)
        card_identification_name = request.form.get('card_identification_name')
        Visitor_ID = request.form.get('Visitor_ID')
        logging.info(f"Visitor_ID received from form: {Visitor_ID}")
        # Refined cleaning logic for Visitor_ID
        if Visitor_ID:
            import re
            # Attempt to extract only digits from the Visitor_ID string
            digits_only = re.sub(r'\D', '', Visitor_ID)
            if digits_only:
                Visitor_ID = digits_only
                logging.info(f"Refined Visitor_ID to numerical: {Visitor_ID}")
            else:
                logging.warning(f"Could not extract numerical ID from '{Visitor_ID}'. Using original.")
        unit = request.form.get('visit_location') # Get unit from visit_location field

        # Materials lists (may be empty)
        material_names = request.form.getlist('material_name[]')
        material_types = request.form.getlist('material_type[]')
        material_makes = request.form.getlist('material_make[]')
        material_serial_numbers = request.form.getlist('material_serial_number[]')
        
        logging.info(f"Purpose: {purpose}")
        logging.info(f"Material form data received:")
        logging.info(f"  Names: {material_names}")
        logging.info(f"  Types: {material_types}")
        logging.info(f"  Makes: {material_makes}")
        logging.info(f"  Serial Numbers: {material_serial_numbers}")

        # File upload paths (filenames stored)
        id_proof_path = None
        visitor_image_path = None
        
        # Handle ID proof file upload (optional)
        if 'id_proof' in request.files:
            file = request.files['id_proof']
            if file and file.filename:
                filename = secure_filename(file.filename)
                allowed = {'.png', '.jpg', '.jpeg', '.pdf'}
                ext = os.path.splitext(filename)[1].lower()
                if ext not in allowed:
                    logging.warning(f"Rejected upload with disallowed extension: {ext}")
                    flash("Unsupported file type for ID proof.", 'error')
                    return render_template('register_visitor.html', employees=employees)
                unique_name = f"id_{(Visitor_ID or 'unknown')}_{uuid4().hex}{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                try:
                    file.save(file_path)
                    id_proof_path = os.path.basename(unique_name)
                    logging.info(f"ID proof saved to {file_path}")
                except Exception as e:
                    logging.error(f"Error saving ID proof file: {e}")
                    flash("Error saving ID proof file.", 'error')
                    return render_template('register_visitor.html', employees=employees)
        
        # Handle captured visitor photo (base64 string in form field 'visitor_photo')
        visitor_photo_data = request.form.get('visitor_photo')
        
        # Validate that visitor photo is provided
        if not visitor_photo_data or not visitor_photo_data.strip():
            flash('Visitor Photo is required.', 'error')
            return render_template('register_visitor.html', employees=employees)
        
        if visitor_photo_data:
            try:
                # Expecting data URI like "data:image/png;base64,....."
                if ',' in visitor_photo_data:
                    header, encoded = visitor_photo_data.split(',', 1)
                else:
                    encoded = visitor_photo_data
                binary_data = base64.b64decode(encoded)
                # Temporarily store binary data and filename, process after visitor is committed
                temp_photo_binary_data = binary_data
                temp_photo_filename_prefix = "visitor_photo"
                logging.info("Visitor photo data received, will save after visitor registration.")
            except Exception as e:
                logging.error(f"Error processing visitor photo: {e}")
                flash("Error processing visitor photo.", 'error')
                return render_template('register_visitor.html', employees=employees)
        
        # Create Visitor object (do not set materials' visitor_id yet)
        new_visitor = Visitor(
            name=name,
            email=email,
            mobile=mobile,
            purpose=purpose,
            host_id=host_id,
            id_proof_path=id_proof_path,
            id_proof_type=final_id_proof_type,
            other_id_proof_type=other_id_proof_type_value,
            visitor_image=visitor_image_path,
            created_by=current_user.id,
            meeting_id=meeting_id,
            requested_by=requested_by,
            no_of_hours=no_of_hours,
            visit_location=visit_location,
            visitor_type=visitor_type,
            company=company_name,  # Use company_name for vendor services, empty for others
            from_datetime=from_datetime,
            to_datetime=to_datetime,
            card_identification_name=card_identification_name,
            access_group_name='',  # Set to empty string since field was removed
            Visitor_ID=Visitor_ID,
            original_visitor_id=request.form.get('Visitor_ID'),
            unit=unit # Assign unit to new_visitor
        )
        # Process and add unique materials to the visitor
        unique_materials_data = set()
        for i in range(len(material_names)):
            name_m = material_names[i].strip() if i < len(material_names) else None
            type_m = material_types[i].strip() if i < len(material_types) else None
            make_m = material_makes[i].strip() if i < len(material_makes) else None
            serial_number_m = material_serial_numbers[i].strip() if i < len(material_serial_numbers) else None

            # Only add if material name is not empty
            if name_m:
                unique_materials_data.add((name_m, type_m, make_m, serial_number_m))

        logging.info(f"Processing {len(unique_materials_data)} unique materials for visitor")
        for name_m, type_m, make_m, serial_number_m in unique_materials_data:
            mat = Material(
                name=name_m,
                type=type_m,
                make=make_m,
                serial_number=serial_number_m,
                visitor_code=Visitor_ID  # Store the same 5-digit Visitor_ID
            )
            new_visitor.materials.append(mat)
            logging.info(f"Added material: {name_m} (Type: {type_m}, Make: {make_m}, Serial: {serial_number_m}, Visitor Code: {Visitor_ID})")

        # Add to DB and commit (so visitor.id is available)
        try:
            db.session.add(new_visitor)
            db.session.commit()
            visitor = new_visitor  # persisted instance
            logging.info(f"Visitor created with ID: {visitor.id}, Visitor_ID: {visitor.Visitor_ID}")
            logging.info(f"Materials saved: {len(visitor.materials)} materials linked to visitor {visitor.id}")
            for mat in visitor.materials:
                logging.info(f"  - Material ID: {mat.id}, Name: {mat.name}, Visitor_ID: {mat.visitor_id}")
            # Ensure check-in time is only set upon approval
            try:
                visitor.check_in_time = None
                visitor.status = visitor.status or 'pending'
                db.session.commit()
            except Exception as ie:
                db.session.rollback()
                logging.error(f"Error normalizing initial visitor state: {ie}")

            # Save visitor photo after visitor object is committed and has an ID
            if visitor_photo_data and 'temp_photo_binary_data' in locals():
                try:
                    photo_filename = f"{temp_photo_filename_prefix}_{visitor.Visitor_ID}.png"
                    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
                    with open(photo_path, 'wb') as f:
                        f.write(temp_photo_binary_data)
                    visitor.visitor_image = photo_filename
                    db.session.commit()
                    logging.info(f"Visitor photo saved: {photo_path}")
                except Exception as e:
                    db.session.rollback()
                    logging.error(f"Error saving visitor photo after commit: {e}")
                    flash("Error saving visitor photo.", 'error')
                    return render_template('register_visitor.html', employees=employees)
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error adding visitor to database: {e}")
            flash("Error adding visitor to database.", 'error')
            return render_template('register_visitor.html', employees=employees)

        # Generate QR code and save file (use visitor.Visitor_ID)
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            unique_data = str(visitor.Visitor_ID)
            qr.add_data(unique_data)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")

            qr_filename = f"qr_visitor_{visitor.Visitor_ID}.png"
            qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
            try:
                logging.info(f"Generating QR code with Visitor_ID: {unique_data}")
                qr_img.save(qr_path)
                visitor.qr_code = qr_filename
                db.session.commit()
                logging.info(f"QR code saved and visitor updated: {qr_filename}")
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error saving QR code or updating visitor: {e}")
        except Exception as e:
            logging.error(f"Error generating QR code: {e}")

        # Send email to visitor with details and QR code
        try:
            if visitor.email:
                subject = "Your Visitor Registration Details"
                # Format the email body as in the image
                body = f"Dear {visitor.name},\n\nHere are your registration details."
                html_body = f"""
            <p>Dear {h(visitor.name)},</p>
            <p>
            Greeting from Vilion Technologies Pvt Ltd!\n<br>
            Your visitor registration is successful. Below are your details:<br>
            </p>
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 15px; font-family: sans-serif;">
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Name</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.name) }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">VisitorType</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.visitor_type or 'N/A') }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Mobile</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.mobile) }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Email</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.email or 'N/A') }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Company</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ visitor.company or 'N/A' }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Purpose</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.purpose or 'N/A') }</td>
                        </tr>
                         <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Visitor ID</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.Visitor_ID) }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Visit Location</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.visit_location or 'N/A') }</td>
                        </tr>
                    </table>
                    <p>Thank you for registering your visit to our organization. Your details have been successfully submitted and are currently awaiting approval from the concerned department.</p>
                    <p>You will receive a confirmation email once your visit request has been reviewed and approved. Please wait for further communication before arriving at our premises.</p>
                    <p>For any urgent inquiries or assistance, please feel free to contact our team</p>
                    <p>Best regards,<br>Vilion Technologies Pvt Ltd</p>
            """
                # Send email in background
                send_email(visitor.email, subject, body, html_body=html_body, visitor=visitor, async_mode=True)
                # Email status not checked due to async mode
            else:
                flash("Visitor email address is missing.", 'warning')
        except Exception as e:
            logging.error(f"Error sending email to visitor: {e}")
            flash("Error sending email to visitor.", 'error')

        # Send approval email to host (if host exists)
        try:
            # Refresh the visitor object to ensure materials are loaded
            db.session.refresh(visitor)
            
            host = User.query.get(host_id) if host_id else None
            host_plain_body = ""  # Initialize host_plain_body
            host_html_body = "" # Initialize host_html_body
            if host and host.email:
                approval_link = url_for('approve_visitor', visitor_id=visitor.id, _external=True)
                rejection_link = url_for('reject_visitor', visitor_id=visitor.id, _external=True)
                
                # Determine who should receive the approval request - HOD if host is not admin
                if host.role != 'admin' and host.department:
                    # Find the HOD for the host's department
                    hod = User.query.filter_by(department=host.department, is_hod=True, is_active=True).first()
                    if hod:
                        approval_recipient = hod
                        host_subject = f"Visitor Approval Request: {visitor.name} for {host.username} (Department: {host.department})"
                    else:
                        # If no HOD found, default to the host
                        approval_recipient = host
                        host_subject = f"Visitor Approval Request: {visitor.name} for {host.username}"
                else:
                    # Admins receive requests directly
                    approval_recipient = host
                    host_subject = f"Visitor Approval Request: {visitor.name} for {host.username}"

                # HTML body (includes visitor photo if available)
                host_html_body += f"""
                    <p>Dear {h(approval_recipient.username)},</p>
                    <p>A new visitor, <strong>{h(visitor.name)}</strong>, has registered to meet {host.username}.</p>
                    
                    <p><strong>Visitor Details:</strong></p>
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 15px; font-family: sans-serif;">
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Name</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.name) }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">VisitorType</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.visitor_type or 'N/A') }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Mobile</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.mobile) }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Email</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.email or 'N/A') }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Company</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.company or 'N/A') }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Purpose</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.purpose or 'N/A') }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Visitor ID</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.Visitor_ID) }</td>
                        </tr>
                        <tr>
                        <td style="padding:4px 15px 4px 4px; font-weight:bold;">Visit Location</td>
                        <td style="padding:4px 8px;">:</td>
                        <td style="padding:4px;">{ h(visitor.visit_location or 'N/A') }</td>
                        </tr>
                    </table>
                """

                # Materials Table
                if visitor.materials:
                    host_html_body += """
                    <p style="margin-top: 20px;"><strong>Material Details:</strong></p>
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 15px; font-family: sans-serif;">
                        <tr style="background-color: #f2f2f2;">
                            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">SI.No</th>
                            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Material Name</th>
                            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Type</th>
                            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Make</th>
                            <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Serial Number</th>
                        </tr>
                    """
                    for i, material in enumerate(visitor.materials):
                        host_html_body += f"""
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd;">{i + 1}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">{h(material.name or 'N/A')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">{h(material.type or 'N/A')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">{h(material.make or 'N/A')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">{h(material.serial_number or 'N/A')}</td>
                        </tr>
                        """
                    host_html_body += "</table>"
                else:
                    host_html_body += '<p style="margin-top: 20px;"><strong>Material Details:</strong> No materials declared.</p>'

                if visitor.visitor_image:
                    host_html_body += f'<p><strong>Visitor Photo:</strong><br><img src="cid:visitor_photo" alt="Visitor Photo" style="max-width:200px;border-radius:5px;"></p>'

                # Add approve/reject buttons
                host_html_body += f"""
                    <p>Please approve or reject this visit:</p>
                    <p>
                        <a href="{approval_link}" style="padding:10px 20px; border-radius:5px; text-decoration:none; background:#28a745; color:#fff;">Approve</a>
                        <a href="{rejection_link}" style="padding:10px 20px; border-radius:5px; text-decoration:none; background:#dc3545; color:#fff; margin-left:10px;">Reject</a>
                    </p>
                    <p>Best regards,<br>VMS Team</p>
                """

                embedded_image_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor.visitor_image) if visitor.visitor_image else None
                send_results = []
                # Send to appropriate approval recipient (HOD or host) in background
                send_email(approval_recipient.email, host_subject, host_plain_body, html_body=host_html_body, visitor=visitor, embedded_image_path=embedded_image_path, embedded_image_cid="visitor_photo", async_mode=True)
                send_results.append(True)  # Assume success in async mode

                # Also send to approvers (all admins) - but not duplicate if HOD is also admin
                approvers = User.query.filter_by(role='admin', is_active=True).all()
                for approver in approvers:
                    # Don't send duplicate email if the HOD is also an admin
                    if approver.email and approver.email != approval_recipient.email:
                        send_email(approver.email, host_subject, host_plain_body, html_body=host_html_body, visitor=visitor, embedded_image_path=embedded_image_path, embedded_image_cid="visitor_photo", async_mode=True)
                        send_results.append(True)  # Assume success in async mode

                # Send notification to the host (employee being visited) about the visitor registration
                host_notification_subject = f"Visitor Registration Notification: {visitor.name} wants to meet you"
                host_notification_body = f"""
Dear {h(host.username)},

A visitor has registered to meet you:

Name: {h(visitor.name)}
Mobile: {h(visitor.mobile)}
Email: {h(visitor.email)}
Purpose: {h(visitor.purpose)}

This visitor is currently awaiting approval from your department head.

Best regards,
VMS Team
"""
                
                host_notification_result = False
                if host.email and host.email != approval_recipient.email:
                    # Don't send duplicate if the host is also the approval recipient (HOD)
                    send_email(host.email, host_notification_subject, host_notification_body, html_body=None, visitor=visitor, async_mode=True)
                    host_notification_result = True  # Assume success in async mode
                    
                if any(send_results):
                    if host_notification_result:
                        flash("Approval email sent to HOD/approvers and notification sent to host.", 'success')
                    else:
                        flash("Approval email sent to HOD/approvers.", 'success')
                else:
                    flash("Failed to send approval email to HOD/approvers.", 'error')
            else:
                flash("Host email address is missing.", 'warning')
        except Exception as e:
            logging.error(f"Error sending approval email to host: {e}")
            flash("Error sending approval email to host.", 'error')

        flash('Visitor registered successfully.', 'success')
        return redirect(url_for('dashboard',_external=True))

    except Exception as e:
        logging.error(f"Unhandled error in register_visitor: {e}")
        flash("An unexpected error occurred while registering the visitor.", 'error')
        return render_template('register_visitor.html', employees=employees)


@app.route('/vms/add_user', methods=['GET', 'POST'])
@rate_limit(limit=20, window=60, name='add_user')
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    if request.method == 'POST':
        employee_id = request.form['employee_id']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        username = request.form['username']
        department = request.form.get('department')
        unit = request.form.get('unit')
        is_hod = 'is_hod' in request.form  # Check if the checkbox is checked
        is_active = 'is_active' in request.form  # Check if the checkbox is checked

        # Password policy: min 8 chars, upper, lower, digit, special
        policy = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$')
        if not policy.match(password or ''):
            flash('Password must be at least 8 characters and include upper, lower, digit, and special character.', 'error')
            return render_template('add_user.html')

        hashed_password = generate_password_hash(password, method='scrypt:32768:8:1')
        new_user = User(employee_id=employee_id, email=email, password_hash=hashed_password, role=role, username=username, department=department, unit=unit, is_hod=is_hod, is_active=is_active)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('user_management',_external=True))
        except IntegrityError:
            db.session.rollback()
            flash('Error: An account with this Employee ID already exists.', 'error')
            return render_template('add_user.html')

    return render_template('add_user.html')


@app.route('/vms/edit_user/<int:user_id>', methods=['GET', 'POST'])
@rate_limit(limit=30, window=60, name='edit_user')
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.employee_id = request.form['employee_id']
        user.email = request.form['email']
        user.role = request.form['role']
        user.username = request.form['username']
        user.department = request.form.get('department')
        user.unit = request.form.get('unit')
        user.is_active = 'is_active' in request.form
        user.is_hod = 'is_hod' in request.form  # Update HOD status

        new_password = request.form.get('password')
        if new_password:
            policy = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$')
            if not policy.match(new_password):
                flash('New password does not meet complexity requirements.', 'error')
                return render_template('edit_user.html', user=user)
            user.password_hash = generate_password_hash(new_password, method='scrypt:32768:8:1')

        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('user_management',_external=True))
        except IntegrityError:
            db.session.rollback()
            flash('Error: An account with this email already exists.', 'error')
            return render_template('edit_user.html', user=user)
    
    return render_template('edit_user.html', user=user)


@app.route('/vms/settings', methods=['GET', 'POST'])
@rate_limit(limit=10, window=60, name='settings')
@login_required
def settings():
    if current_user.role != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    if request.method == 'POST':
        company_name = request.form.get('company_name')
        system_title = request.form.get('system_title')
        mail_server = request.form.get('mail_server')
        mail_port = request.form.get('mail_port', type=int)
        mail_use_tls = 'mail_use_tls' in request.form
        mail_username = request.form.get('mail_username')
        mail_password = request.form.get('mail_password')
        mail_default_sender = request.form.get('mail_default_sender')

        set_setting('company_name', company_name)
        set_setting('system_title', system_title)
        set_setting('MAIL_SERVER', mail_server)
        set_setting('MAIL_PORT', str(mail_port)) # Store as string
        set_setting('MAIL_USE_TLS', '1' if mail_use_tls else '0') # Store as string
        set_setting('MAIL_USERNAME', mail_username)
        set_setting('MAIL_PASSWORD', mail_password)
        set_setting('MAIL_DEFAULT_SENDER', mail_default_sender)

        # Update app.config with new settings immediately
        app.config['MAIL_SERVER'] = mail_server
        app.config['MAIL_PORT'] = mail_port
        app.config['MAIL_USE_TLS'] = mail_use_tls
        app.config['MAIL_USERNAME'] = mail_username
        app.config['MAIL_PASSWORD'] = mail_password
        app.config['MAIL_DEFAULT_SENDER'] = mail_default_sender

        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings',_external=True))

    # Retrieve current settings for GET request
    current_settings = {
    'company_name': get_setting('company_name', 'VMS Pro'),
    'system_title': get_setting('system_title', 'Visitor Management System'),
    'MAIL_SERVER': get_setting('MAIL_SERVER', 'smtp.office365.com'),
    'MAIL_PORT': int(get_setting('MAIL_PORT', '587')),
    'MAIL_USE_TLS': get_setting('MAIL_USE_TLS', '1') == '1',
    'MAIL_USERNAME': get_setting('MAIL_USERNAME', 'sapnoreply@violintec.com'),
    'MAIL_PASSWORD': get_setting('MAIL_PASSWORD', 'VT$ofT@$2025'),
    'MAIL_DEFAULT_SENDER': get_setting('sapnoreply@violintec.com')
}
    return render_template('settings.html', settings=current_settings)


@app.route('/vms/delete_user/<int:user_id>', methods=['POST'])
@rate_limit(limit=10, window=60, name='delete_user')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('user_management',_external=True))


@app.route('/vms/delete_visitor/<visitor_id>', methods=['POST'])
@rate_limit(limit=10, window=60, name='delete_visitor')
@login_required
def delete_visitor(visitor_id):
    if current_user.role != 'admin':
        flash('Access denied! Only admin can delete visitors.', 'error')
        return redirect(url_for('dashboard',_external=True))

    visitor = Visitor.query.filter_by(Visitor_ID=visitor_id).first_or_404()

    try:
            # Delete associated files
            if visitor.id_proof_path:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor.id_proof_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logging.info(f"Deleted ID proof file: {file_path}")
                else:
                    logging.warning(f"ID proof file not found, skipping deletion: {file_path}")
            if visitor.visitor_image:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor.visitor_image)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logging.info(f"Deleted visitor image file: {file_path}")
                else:
                    logging.warning(f"Visitor image file not found, skipping deletion: {file_path}")
            if visitor.qr_code:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor.qr_code)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logging.info(f"Deleted QR code file: {file_path}")
                else:
                    logging.warning(f"QR code file not found, skipping deletion: {file_path}")

            db.session.delete(visitor)
            db.session.commit()
            flash(f'Visitor {visitor.name} (ID: {visitor.Visitor_ID}) deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting visitor: {e}")
        flash('Error deleting visitor.', 'error')
    return redirect(url_for('visitor_status',_external=True))


@app.route('/vms/display_qr_code/<string:visitor_id>')
@rate_limit(limit=30, window=60, name='display_qr')
@login_required
def display_qr_code(visitor_id):
    logging.info(f"Attempting to display QR code for visitor_id: '{visitor_id}'")

    # Try to find visitor by original ID first, then by cleaned ID
    visitor = Visitor.query.filter(
        db.or_(
            Visitor.Visitor_ID == visitor_id,
            Visitor.original_visitor_id == visitor_id
        )
    ).first()

    # If not found, try with cleaned ID (digits only)
    if not visitor:
        cleaned_visitor_id = re.sub(r'\D', '', visitor_id)
        logging.info(f"Visitor not found with raw ID '{visitor_id}', trying cleaned_visitor_id: '{cleaned_visitor_id}'")
        
        if cleaned_visitor_id:
            visitor = Visitor.query.filter(Visitor.Visitor_ID == cleaned_visitor_id).first()

    if not visitor:
        logging.warning(f"Visitor with ID '{visitor_id}' not found in database after all attempts.")
        flash('Visitor not found!', 'error')
        return redirect(url_for('visitor_status',_external=True))

    logging.info(f"Visitor found: {visitor.name} (DB ID: {visitor.id}, Stored Visitor_ID: {visitor.Visitor_ID})")

    # Authorization: admin allowed; security only if same unit; employee only if host
    if not (
        (current_user.role == 'admin') or
        (current_user.role == 'security' and getattr(visitor, 'unit', None) == current_user.unit) or
        (current_user.role == 'employee' and visitor.host_id == current_user.id)
    ):
        flash('Access denied to QR code.', 'error')
        return redirect(url_for('dashboard', _external=True))

    if visitor.qr_code:
        qr_code_filename = visitor.qr_code
        qr_code_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_code_filename)
        logging.info(f"Attempting to serve QR code file: '{qr_code_filename}' from path: '{qr_code_path}'")
        
        if os.path.exists(qr_code_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], qr_code_filename)
        else:
            logging.warning(f"QR code file '{qr_code_filename}' not found on disk at '{qr_code_path}'. Attempting to regenerate.")
            # Fall through to regeneration logic
    else:
        logging.warning(f"QR code path missing in database for Visitor_ID: {visitor.Visitor_ID}. Attempting to regenerate.")

    # If QR code path is missing or file not found, try to regenerate it
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        unique_data = str(visitor.Visitor_ID)
        qr.add_data(unique_data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")

        qr_filename = f"qr_visitor_{visitor.Visitor_ID}.png"
        qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
        qr_img.save(qr_path)
        visitor.qr_code = qr_filename
        db.session.commit()
        logging.info(f"QR code regenerated and saved: '{qr_filename}' for Visitor_ID: {visitor.Visitor_ID}")
        return send_from_directory(app.config['UPLOAD_FOLDER'], qr_filename)
    except Exception as e:
        logging.error(f"Error regenerating QR code for Visitor_ID {visitor.Visitor_ID}: {e}", exc_info=True)
        flash('QR code not found and failed to regenerate.', 'error')
        return redirect(url_for('visitor_status',_external=True))


@app.route('/vms/public_visitor_image/<string:visitor_id>/<string:image_type>')
@rate_limit(limit=100, window=60, name='public_image')
def public_visitor_image(visitor_id, image_type):
    """Public route to serve visitor images and QR codes for printing purposes"""
    logging.info(f"Attempting to serve public image for visitor_id: '{visitor_id}', image_type: '{image_type}'")

    # Try to find visitor by original ID first, then by cleaned ID
    visitor = Visitor.query.filter(
        db.or_(
            Visitor.Visitor_ID == visitor_id,
            Visitor.original_visitor_id == visitor_id
        )
    ).first()

    # If not found, try with cleaned ID (digits only)
    if not visitor:
        cleaned_visitor_id = re.sub(r'\D', '', visitor_id)
        logging.info(f"Visitor not found with raw ID '{visitor_id}', trying cleaned_visitor_id: '{cleaned_visitor_id}'")
        
        if cleaned_visitor_id:
            visitor = Visitor.query.filter(Visitor.Visitor_ID == cleaned_visitor_id).first()

    if not visitor:
        logging.warning(f"Visitor with ID '{visitor_id}' not found in database.")
        abort(404)

    # Security check: only serve images for approved, checked-in, or exited visitors
    if visitor.status not in ['approved', 'checked-in', 'exited']:
        logging.warning(f"Attempt to access image for visitor with status '{visitor.status}'")
        abort(403)

    if image_type == 'qr':
        if visitor.qr_code:
            qr_code_filename = visitor.qr_code
            qr_code_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_code_filename)
            logging.info(f"Attempting to serve QR code file: '{qr_code_filename}' from path: '{qr_code_path}'")
            
            if os.path.exists(qr_code_path):
                return send_from_directory(app.config['UPLOAD_FOLDER'], qr_code_filename)
            else:
                logging.warning(f"QR code file '{qr_code_filename}' not found on disk at '{qr_code_path}'. Attempting to regenerate.")
                # Try to regenerate it
                try:
                    qr = qrcode.QRCode(version=1, box_size=10, border=5)
                    unique_data = str(visitor.Visitor_ID)
                    qr.add_data(unique_data)
                    qr.make(fit=True)
                    qr_img = qr.make_image(fill_color="black", back_color="white")

                    qr_filename = f"qr_visitor_{visitor.Visitor_ID}.png"
                    qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
                    qr_img.save(qr_path, )
                    visitor.qr_code = qr_filename
                    db.session.commit()
                    logging.info(f"QR code regenerated and saved: '{qr_filename}' for Visitor_ID: {visitor.Visitor_ID}")
                    return send_from_directory(app.config['UPLOAD_FOLDER'], qr_filename)
                except Exception as e:
                    logging.error(f"Error regenerating QR code for Visitor_ID {visitor.Visitor_ID}: {e}", exc_info=True)
                    abort(500)
        else:
            logging.warning(f"QR code path missing in database for Visitor_ID: {visitor.Visitor_ID}")
            abort(404)
            
    elif image_type == 'photo':
        if visitor.visitor_image:
            visitor_image_filename = visitor.visitor_image
            visitor_image_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor_image_filename)
            logging.info(f"Attempting to serve visitor image file: '{visitor_image_filename}' from path: '{visitor_image_path}'")
            
            if os.path.exists(visitor_image_path):
                return send_from_directory(app.config['UPLOAD_FOLDER'], visitor_image_filename)
            else:
                logging.warning(f"Visitor image file '{visitor_image_filename}' not found on disk at '{visitor_image_path}'")
                abort(404)
        else:
            logging.warning(f"Visitor image path missing in database for Visitor_ID: {visitor.Visitor_ID}")
            abort(404)
    else:
        logging.warning(f"Invalid image_type parameter: '{image_type}'")
        abort(400)


@app.route('/vms/approve_visitor/<int:visitor_id>', methods=['GET','POST'])
@rate_limit(limit=20, window=60, name='approve')
@login_required
def approve_visitor(visitor_id):
    visitor = Visitor.query.get_or_404(visitor_id)
    
    # Check if current user is admin, the host, or the HOD of the host's department
    host = User.query.get(visitor.host_id)
    is_hod_of_host_department = False
    
    if host and current_user.is_hod and current_user.department == host.department:
        is_hod_of_host_department = True
    
    # Only allow admin or HOD of the host's department to approve
    if not (current_user.role == 'admin' or is_hod_of_host_department):
        flash('Access denied! Only admin or HOD can approve visitors.', 'error')
        return redirect(url_for('approval_dashboard',_external=True))
    visitor.status = 'approved'
    visitor.approved_at = datetime.now(IST_TIMEZONE) # Set the approval timestamp
    visitor.approved_by_id = current_user.id  # Set who approved the visitor
    db.session.commit()

    # Send email to visitor with details and QR code
    try:
        if visitor.email:
            subject = "Your Visitor Registration Approved - Vilion Technologies Pvt Ltd"
            
            # Ensure QR code exists, generate if missing
            if not visitor.qr_code:
                try:
                    qr = qrcode.QRCode(version=1, box_size=10, border=5)
                    unique_data = str(visitor.Visitor_ID)
                    qr.add_data(unique_data)
                    qr.make(fit=True)
                    qr_img = qr.make_image(fill_color="black", back_color="white")

                    qr_filename = f"qr_visitor_{visitor.Visitor_ID}.png"
                    qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
                    qr_img.save(qr_path)
                    visitor.qr_code = qr_filename
                    db.session.commit()
                    logging.info(f"QR code generated and saved for approved visitor: {qr_filename}")
                except Exception as e:
                    logging.error(f"Error generating QR code for approved visitor: {e}")
                    visitor.qr_code = None
            
            # Construct the full path to the QR code
            qr_code_path = os.path.join(app.config['UPLOAD_FOLDER'], visitor.qr_code) if visitor.qr_code else None
            
            # Debug logging
            logging.info(f"QR Code file: {visitor.qr_code}")
            logging.info(f"QR Code path: {qr_code_path}")
            logging.info(f"QR Code exists: {os.path.exists(qr_code_path) if qr_code_path else False}")

            # Construct HTML body for the email with prominent QR code
            html_body = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                <div style="background-color: #007bff; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h2 style="margin: 0;">Visitor Registration Approved</h2>
                </div>
                <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <p style="font-size: 16px;">Dear <strong>{visitor.name}</strong>,</p>
                    <p style="font-size: 16px; line-height: 1.6;">
                        Greeting from <strong>Vilion Technologies Pvt Ltd</strong>!<br><br>
                        Your visitor registration has been <strong style="color: #28a745;">APPROVED</strong>. 
                        You can now proceed with your visit.
                    </p>
                    
                    <div style="background-color: #e7f3ff; padding: 20px; border-left: 4px solid #007bff; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Visitor ID:</strong> {visitor.Visitor_ID}</p>
                        <p style="margin: 5px 0;"><strong>Name:</strong> {visitor.name}</p>
                        <p style="margin: 5px 0;"><strong>Company:</strong> {visitor.company or 'N/A'}</p>
                        <p style="margin: 5px 0;"><strong>Purpose:</strong> {visitor.purpose or 'N/A'}</p>
                        <p style="margin: 5px 0;"><strong>Visit Date:</strong> {visitor.from_datetime.strftime('%b %d, %Y %I:%M %p') if visitor.from_datetime else 'N/A'}</p>
                    </div>
            """            
            if qr_code_path and os.path.exists(qr_code_path):
                qr_cid = f"qr_code_{visitor.Visitor_ID}"
                html_body += f"""
                    <div style="text-align: center; margin: 30px 0; padding: 20px; background-color: #f8f9fa; border-radius: 10px;">
                        <h3 style="color: #007bff; margin-bottom: 15px;">📱 Your Check-in QR Code</h3>
                        <p style="margin-bottom: 20px; color: #666;">
                            Please show this QR code at the reception for quick check-in:
                        </p>
                        <div style="background-color: white; padding: 20px; display: inline-block; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                            <img src="cid:{qr_cid}" alt="QR Code" style="width: 250px; height: 250px; display: block; margin: 0 auto; border: 2px solid #007bff;">
                        </div>
                        <p style="margin-top: 15px; font-size: 18px; font-weight: bold; color: #007bff;">
                            Visitor ID: {visitor.Visitor_ID}
                        </p>
                    </div>
                """
                logging.info(f"QR Code HTML added with CID reference: cid:{qr_cid}")
            else:
                qr_cid = None
                html_body += """
                    <div style="text-align: center; padding: 20px; background-color: #fff3cd; border-radius: 10px; margin: 20px 0;">
                        <p style="color: #856404; margin: 0;">⚠️ QR code could not be attached. Please contact support.</p>
                    </div>
                """

            html_body += """
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                        <p style="font-size: 14px; color: #666;">
                            <strong>Important Instructions:</strong>
                        </p>
                        <ul style="color: #666; font-size: 14px; line-height: 1.8;">
                            <li>Please arrive on time for your scheduled visit</li>
                            <li>Show this QR code at the reception desk</li>
                            <li>Carry a valid photo ID for verification</li>
                            <li>Follow all security protocols during your visit</li>
                        </ul>
                    </div>
                    
                    <p style="margin-top: 30px; font-size: 16px;">We look forward to your visit!</p>
                    <p style="font-size: 16px;">
                        Best regards,<br>
                        <strong>Vilion Technologies Pvt Ltd</strong>
                    </p>
                </div>
                <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
                    <p>This is an automated email. Please do not reply to this message.</p>
                </div>
            </div>
            """
            
            plain_body = f"""
════════════════════════════════════════════════════════════
    VISITOR REGISTRATION APPROVED
════════════════════════════════════════════════════════════

Dear {visitor.name},

Greeting from Vilion Technologies Pvt Ltd!

Your visitor registration has been APPROVED. You can now proceed with your visit.

═══ VISIT DETAILS ═══
Visitor ID: {visitor.Visitor_ID}
Name: {visitor.name}
Company: {visitor.company or 'N/A'}
Purpose: {visitor.purpose or 'N/A'}
Visit Date: {visitor.from_datetime.strftime('%b %d, %Y %I:%M %p') if visitor.from_datetime else 'N/A'}

═══ YOUR CHECK-IN QR CODE ═══
Your QR code is attached to this email. Please show it at the reception desk for quick check-in.

IMPORTANT INSTRUCTIONS:
• Please arrive on time for your scheduled visit
• Show the QR code at the reception desk
• Carry a valid photo ID for verification
• Follow all security protocols during your visit

We look forward to your visit!

Best regards,
Vilion Technologies Pvt Ltd

════════════════════════════════════════════════════════════
This is an automated email. Please do not reply to this message.
════════════════════════════════════════════════════════════
            """

            # Send email in background
            send_email(visitor.email, subject, plain_body, html_body=html_body, embedded_image_path=qr_code_path, embedded_image_cid=qr_cid, async_mode=True)
            # Email status not checked due to async mode
        else:
            flash("Visitor email address is missing, cannot send approval email.", 'warning')
    except Exception as e:
        logging.error(f"Error sending approval email to visitor: {e}")
        flash("Error sending approval email to visitor.", 'error')

    flash(f'Visitor {visitor.name} approved.', 'success')
    # The return statement should always be executed after all operations
    return redirect(url_for('approval_dashboard',_external=True))


@app.route('/vms/reject_visitor/<int:visitor_id>', methods=['GET','POST'])
@rate_limit(limit=20, window=60, name='reject')
@login_required
def reject_visitor(visitor_id):
    visitor = Visitor.query.get_or_404(visitor_id)
    if not (current_user.role == 'admin' or visitor.host_id == current_user.id):
        flash('Access denied!', 'error')
        return redirect(url_for('approval_dashboard',_external=True))
    visitor.status = 'rejected'
    db.session.commit()
    flash(f'Visitor {visitor.name} rejected.', 'info')
    return redirect(url_for('approval_dashboard',_external=True))


@app.route('/vms/reject_visitor_by_qrcode/<string:visitor_id>', methods=['POST'])
@login_required
def reject_visitor_by_qrcode(visitor_id):
    if current_user.role not in ['admin', 'security']:
        return jsonify(success=False, message='Access denied!'), 403

    visitor = Visitor.query.filter_by(Visitor_ID=visitor_id).first()
    if not visitor:
        return jsonify(success=False, message='Visitor not found!'), 404

    try:
        visitor.status = 'rejected'
        db.session.commit()
        logging.info(f"Visitor {visitor.name} (Visitor_ID: {visitor_id}) rejected by QR code.")
        return jsonify(success=True, message=f'Visitor {visitor.name} (ID: {visitor_id}) rejected successfully.'), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error rejecting visitor {visitor_id} by QR code: {e}")
        return jsonify(success=False, message=f"Error rejecting visitor: {e}"), 500


@app.route('/vms/mark_exited/<string:visitor_id>')
@login_required
def mark_exited(visitor_id):
    if current_user.role not in ['admin', 'security']:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard',_external=True))

    visitor = Visitor.query.filter_by(Visitor_ID=visitor_id).first_or_404()
    if current_user.role == 'security' and visitor.unit != current_user.unit:
        flash('Access denied to mark exited for other units.', 'error')
        return redirect(url_for('dashboard', _external=True))
    
    if visitor.status == 'approved' or visitor.status == 'checked-in':
        visitor.status = 'exited'
        visitor.check_out_time = datetime.now(IST_TIMEZONE)
        db.session.commit()
        flash(f'Visitor {visitor.name} (ID: {visitor.Visitor_ID}) marked as exited.', 'success')
    else:
        flash(f'Visitor {visitor.name} (ID: {visitor.Visitor_ID}) cannot be marked as exited from status "{visitor.status}".', 'error')
    
    return redirect(url_for('dashboard',_external=True))

@app.route('/vms/uploads/<filename>')
@rate_limit(limit=30, window=60, name='uploads')
@login_required
def uploaded_file(filename):
    filename = os.path.basename(filename)
    visitor = Visitor.query.filter(
        db.or_(
            Visitor.id_proof_path == filename,
            Visitor.visitor_image == filename,
            Visitor.qr_code == filename
        )
    ).first()
    if not visitor:
        abort(404)
    if not (
        (current_user.role == 'admin') or
        (current_user.role == 'security' and getattr(visitor, 'unit', None) == current_user.unit) or
        (current_user.role == 'employee' and visitor.host_id == current_user.id)
    ):
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route("/vms/")
def index():
    if current_user.is_authenticated:
        # return "<h3>logged in</h3>"
        return redirect(url_for('dashboard',_external=True))
    else:
        # return "<h3>login page</h3>"
        return redirect(url_for('login',_external=True))

# Report route for MIS reports
@app.route('/vms/reports')
@login_required
def reports():
    from sqlalchemy.orm import joinedload
    
    # Get the date range from request parameters, default to current date
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    report_type = request.args.get('report_type', 'daily')  # daily, weekly, monthly
    
    # Get filter parameters from request
    unit_filter = request.args.get('unit_filter')
    host_filter = request.args.get('host_filter')
    
    # Set default date range based on report type
    if start_date_str and end_date_str:
        # Use dates from form submission
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    else:
        # Calculate default dates based on report type
        today = datetime.now(IST_TIMEZONE).date()
        if report_type == 'daily':
            start_date = today
            end_date = today
        elif report_type == 'weekly':
            start_date = today - timedelta(days=today.weekday())  # Monday of current week
            end_date = start_date + timedelta(days=6)
        elif report_type == 'monthly':
            start_date = today.replace(day=1)  # First day of current month
            # Calculate last day of month
            if today.month == 12:
                end_date = today.replace(month=12, day=31)
            else:
                end_date = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        else:
            start_date = today
            end_date = today
    
    # Query visitors based on role and date range
    query = Visitor.query
    
    # Filter by date range (check_in_time)
    start_datetime = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=IST_TIMEZONE)
    end_datetime = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=IST_TIMEZONE)
    query = query.filter(Visitor.check_in_time.between(start_datetime, end_datetime))
    
    # Apply unit filter if provided
    if unit_filter and unit_filter != 'all':
        query = query.filter(Visitor.unit == unit_filter)
    
    # Apply host filter if provided
    if host_filter and host_filter != 'all':
        query = query.filter(Visitor.host_id == host_filter)
    
    # Apply role-based filters
    if current_user.role == 'admin':
        # Admin can see all visitors
        pass
    elif current_user.role == 'security':
        # Security can see visitors for their unit
        query = query.filter(Visitor.unit == current_user.unit)
    elif current_user.role == 'employee':
        # Employee can see visitors they hosted
        query = query.filter(Visitor.host_id == current_user.id)
    
    # Get visitors with all required data
    visitors = query.options(joinedload(Visitor.host), joinedload(Visitor.approved_by_user)).order_by(Visitor.check_in_time.desc()).all()
    
    # Get all users for the host filter dropdown
    users = User.query.filter_by(is_active=True).all()
    
    # Calculate additional data like in-office time
    report_data = []
    for visitor in visitors:
        in_office_time = "N/A"
        if visitor.check_in_time and visitor.check_out_time:
            duration = visitor.check_out_time - visitor.check_in_time
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            in_office_time = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        elif visitor.check_in_time:
            # Calculate time from check-in to now
            # Make DB datetime timezone-aware before subtraction
            check_in_time = visitor.check_in_time
            if check_in_time.tzinfo is None:
                check_in_time = check_in_time.replace(tzinfo=IST_TIMEZONE)

            duration = datetime.now(IST_TIMEZONE) - check_in_time
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            in_office_time = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d} (still in office)"
        
        # Get the user who approved the visitor (if available)
        approved_by = 'N/A'
        if visitor.approved_by_user:
            approved_by = visitor.approved_by_user.username
        
        report_data.append({
            'name': visitor.name,
            'host': visitor.host.username if visitor.host else 'N/A',
            'unit': visitor.unit if visitor.unit else 'N/A',
            'check_in_time': visitor.check_in_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_in_time else 'N/A',
            'check_out_time': visitor.check_out_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_out_time else 'N/A',
            'in_office_time': in_office_time,
            'purpose': visitor.purpose,
            'status': visitor.status,
            'approved_by': approved_by
        })
    
    return render_template('reports.html', 
                           report_data=report_data, 
                           start_date=start_date, 
                           end_date=end_date, 
                           report_type=report_type,
                           users=users)


@app.route('/vms/reports/export_csv')
@login_required
def export_reports_csv():
    from sqlalchemy.orm import joinedload
    import csv
    from io import StringIO
    
    # Get the date range from request parameters
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    report_type = request.args.get('report_type', 'daily')  # daily, weekly, monthly
    
    # Get filter parameters from request
    unit_filter = request.args.get('unit_filter')
    host_filter = request.args.get('host_filter')
    
    # Parse date range
    if start_date_str and end_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    else:
        # Calculate default dates based on report type
        today = datetime.now(IST_TIMEZONE).date()
        if report_type == 'daily':
            start_date = today
            end_date = today
        elif report_type == 'weekly':
            start_date = today - timedelta(days=today.weekday())  # Monday of current week
            end_date = start_date + timedelta(days=6)
        elif report_type == 'monthly':
            start_date = today.replace(day=1)  # First day of current month
            # Calculate last day of month
            if today.month == 12:
                end_date = today.replace(month=12, day=31)
            else:
                end_date = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        else:
            start_date = today
            end_date = today
    
    # Query visitors based on role and date range
    query = Visitor.query
    
    # Filter by date range (check_in_time)
    start_datetime = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=IST_TIMEZONE)
    end_datetime = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=IST_TIMEZONE)
    query = query.filter(Visitor.check_in_time.between(start_datetime, end_datetime))
    
    # Apply unit filter if provided
    if unit_filter and unit_filter != 'all':
        query = query.filter(Visitor.unit == unit_filter)
    
    # Apply host filter if provided
    if host_filter and host_filter != 'all':
        query = query.filter(Visitor.host_id == host_filter)
    
    # Apply role-based filters
    if current_user.role == 'admin':
        # Admin can see all visitors
        pass
    elif current_user.role == 'security':
        # Security can see visitors for their unit
        query = query.filter(Visitor.unit == current_user.unit)
    elif current_user.role == 'employee':
        # Employee can see visitors they hosted
        query = query.filter(Visitor.host_id == current_user.id)
    
    # Get visitors with all required data
    visitors = query.options(joinedload(Visitor.host), joinedload(Visitor.created_by_user), joinedload(Visitor.approved_by_user)).order_by(Visitor.check_in_time.desc()).all()
    
    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Visitor Name', 'Whom to Meet', 'Unit', 'Check-in Time', 'Check-out Time', 'In Office Time', 'Purpose of Visit', 'Status', 'Approved By'])
    
    # Write data rows
    for visitor in visitors:
        in_office_time = "N/A"
        if visitor.check_in_time and visitor.check_out_time:
            duration = visitor.check_out_time - visitor.check_in_time
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            in_office_time = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        elif visitor.check_in_time:
            # Calculate time from check-in to now
            # Make DB datetime timezone-aware before subtraction
            check_in_time = visitor.check_in_time
            
            if check_in_time.tzinfo is None:
                check_in_time = check_in_time.replace(tzinfo=IST_TIMEZONE)

            duration = datetime.now(IST_TIMEZONE) - check_in_time
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            in_office_time = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d} (still in office)"
        
        # Get the user who approved the visitor (if available)
        approved_by = 'N/A'
        if visitor.approved_by_user:
            approved_by = visitor.approved_by_user.username
        
        writer.writerow([
            visitor.name,
            visitor.host.username if visitor.host else 'N/A',
            visitor.unit if visitor.unit else 'N/A',
            visitor.check_in_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_in_time else 'N/A',
            visitor.check_out_time.strftime('%Y-%m-%d %H:%M:%S') if visitor.check_out_time else 'N/A',
            in_office_time,
            visitor.purpose,
            visitor.status,
            approved_by
        ])
    
    # Get the CSV string and convert to bytes
    csv_data = output.getvalue()
    output.close()
    
    # Create response with CSV data
    response = Response(csv_data, mimetype='text/csv')
    response.headers['Content-Disposition'] = f'attachment; filename=visitor_report_{start_date_str}_to_{end_date_str}.csv'
    
    return response


# Test email endpoint
@app.route('/vms/test_email')
@login_required
def test_email():
    if current_user.role != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard', _external=True))
    
    try:
        # Send a test email
        to_email = 'keerthana.u@violintec.com'
        subject = 'Test Email from VMS Pro'
        body = 'This is a test email from the Visitor Management System to verify email functionality.'
        html_body = '''
        <html>
            <body>
                <h2>Test Email from VMS Pro</h2>
                <p>This is a test email from the Visitor Management System to verify email functionality.</p>
                <p>If you received this email, the SMTP configuration is working correctly.</p>
                <p>Best regards,<br>VMS Pro Team</p>
            </body>
        </html>
        '''
        
        # Use async mode to prevent blocking
        send_email(to_email, subject, body, html_body=html_body, async_mode=True)
        
        flash(f'Test email sent to {to_email}. Check server logs for delivery status.', 'success')
    except Exception as e:
        flash(f'Error sending test email: {str(e)}', 'error')
    
    return redirect(url_for('dashboard', _external=True))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
