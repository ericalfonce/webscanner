"""
MulikaScans — Production Authentication System
JWT tokens, bcrypt passwords, 2FA (TOTP), email verification,
password reset, rate limiting, RBAC decorators.
"""

import os
import re
import uuid
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timezone, timedelta
from functools import wraps

import jwt
import bcrypt
from flask import (Blueprint, render_template, request, redirect,
                   session, jsonify, url_for, current_app, make_response)
from flask_mail import Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models import db, User, Subscription

auth_bp = Blueprint("auth", __name__)

# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiter (shared instance — initialised in app.py)
# ─────────────────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[])


# ─────────────────────────────────────────────────────────────────────────────
# Password Validation
# ─────────────────────────────────────────────────────────────────────────────
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&_\-])[A-Za-z\d@$!%*#?&_\-]{8,}$"
)

def validate_password(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not PASSWORD_REGEX.match(password):
        return False, ("Password must contain at least one uppercase letter, "
                       "one lowercase letter, one number, and one special character.")
    return True, None


# ─────────────────────────────────────────────────────────────────────────────
# JWT Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _jwt_secret():
    return os.environ.get("JWT_SECRET_KEY", "fallback-dev-secret")


def generate_access_token(user_id: int, role: str) -> str:
    expires = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 900))
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(seconds=expires),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def generate_refresh_token(user_id: int) -> str:
    expires = int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES", 604800))
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(seconds=expires),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def _set_auth_cookies(response, access_token: str, refresh_token: str):
    """Store tokens in HttpOnly cookies."""
    is_prod = os.environ.get("FLASK_ENV") == "production"
    response.set_cookie(
        "access_token", access_token,
        httponly=True, secure=is_prod, samesite="Lax",
        max_age=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 900))
    )
    response.set_cookie(
        "refresh_token", refresh_token,
        httponly=True, secure=is_prod, samesite="Lax",
        max_age=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES", 604800))
    )


def _clear_auth_cookies(response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")


# ─────────────────────────────────────────────────────────────────────────────
# Current User Helper
# ─────────────────────────────────────────────────────────────────────────────
def get_current_user() -> User | None:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        return None
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        return None
    return db.session.get(User, payload["sub"])


# ─────────────────────────────────────────────────────────────────────────────
# RBAC Decorators
# ─────────────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Decorator: @require_role('pro', 'enterprise', 'admin')"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.is_json:
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("auth.login"))
            if user.role not in roles:
                if request.is_json:
                    return jsonify({
                        "error": "Plan upgrade required",
                        "required_roles": list(roles),
                        "current_role": user.role,
                        "upgrade_url": "/pricing"
                    }), 403
                return redirect("/pricing")
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_active_subscription(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        if user.role == "free":
            return redirect("/pricing")
        if user.subscription_status in ("past_due", "cancelled", None) and user.role != "admin":
            if request.is_json:
                return jsonify({"error": "Active subscription required", "upgrade_url": "/pricing"}), 402
            return redirect("/pricing")
        return f(*args, **kwargs)
    return decorated


def require_email_verified(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        if not user.email_verified:
            if request.is_json:
                return jsonify({"error": "Email verification required"}), 403
            return render_template("auth/verify_email_notice.html", email=user.email)
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Email Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _send_email(subject: str, recipients: list, body_html: str):
    try:
        from flask_mail import Message as MailMessage
        mail = current_app.extensions.get("mail")
        if not mail:
            current_app.logger.warning("Flask-Mail not configured — email not sent")
            return
        msg = MailMessage(subject, recipients=recipients, html=body_html)
        mail.send(msg)
    except Exception as e:
        current_app.logger.warning(f"Email send failed: {e}")


def send_verification_email(user: User):
    token = user.verification_token
    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5000")
    link = f"{frontend_url}/verify-email/{token}"
    html = f"""
    <div style="font-family:sans-serif;max-width:600px;margin:auto;background:#0f172a;color:#e5e7eb;padding:40px;border-radius:12px;">
        <h2 style="color:#22d3ee;">Welcome to MulikaScans</h2>
        <p>Thank you for registering. Please verify your email address to activate your account.</p>
        <a href="{link}" style="display:inline-block;background:#22d3ee;color:#0f172a;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;margin:20px 0;">
            Verify Email Address
        </a>
        <p style="color:#64748b;font-size:12px;">This link expires in 24 hours. If you did not create an account, ignore this email.</p>
        <hr style="border-color:#1e293b;">
        <p style="color:#64748b;font-size:12px;">© 2026 MulikaScans by IklwaLabs. All rights reserved.</p>
    </div>
    """
    _send_email("Verify your MulikaScans account", [user.email], html)


def send_password_reset_email(user: User):
    token = user.reset_token
    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5000")
    link = f"{frontend_url}/reset-password/{token}"
    html = f"""
    <div style="font-family:sans-serif;max-width:600px;margin:auto;background:#0f172a;color:#e5e7eb;padding:40px;border-radius:12px;">
        <h2 style="color:#22d3ee;">Password Reset Request</h2>
        <p>We received a request to reset your MulikaScans password. Click the button below to reset it.</p>
        <a href="{link}" style="display:inline-block;background:#22d3ee;color:#0f172a;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;margin:20px 0;">
            Reset Password
        </a>
        <p style="color:#64748b;font-size:12px;">This link expires in 1 hour. If you did not request a password reset, ignore this email.</p>
        <hr style="border-color:#1e293b;">
        <p style="color:#64748b;font-size:12px;">© 2026 MulikaScans by IklwaLabs. All rights reserved.</p>
    </div>
    """
    _send_email("Reset your MulikaScans password", [user.email], html)


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        username = request.form.get("username", "").strip() or None

        # Validate
        if not email or "@" not in email:
            return render_template("auth/register.html", error="Invalid email address.")

        valid, err = validate_password(password)
        if not valid:
            return render_template("auth/register.html", error=err, email=email)

        if User.query.filter_by(email=email).first():
            return render_template("auth/register.html", error="An account with this email already exists.")

        if username and User.query.filter_by(username=username).first():
            return render_template("auth/register.html", error="Username already taken.", email=email)

        # Hash password
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        # Create user
        user = User(
            email=email,
            username=username,
            password_hash=password_hash,
            role="free",
            email_verified=False,
            verification_token=secrets.token_urlsafe(32),
            monthly_scan_limit=2,
        )
        db.session.add(user)

        # Create free subscription record
        sub = Subscription(user=user, plan="free", status="active")
        db.session.add(sub)
        db.session.commit()

        # Send verification email
        send_verification_email(user)

        return render_template("auth/register_success.html", email=email)

    return render_template("auth/register.html")


# ─────────────────────────────────────────────────────────────────────────────
# Email Verification
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return render_template("auth/verify_email.html", success=False,
                               error="Invalid or expired verification link.")
    user.email_verified = True
    user.verification_token = None
    db.session.commit()
    return render_template("auth/verify_email.html", success=True)


@auth_bp.route("/resend-verification", methods=["POST"])
@limiter.limit("3 per hour")
def resend_verification():
    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first()
    if user and not user.email_verified:
        user.verification_token = secrets.token_urlsafe(32)
        db.session.commit()
        send_verification_email(user)
    return render_template("auth/verify_email_notice.html",
                           email=email, resent=True)


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            return render_template("auth/login.html",
                                   error="Invalid email or password.")

        if not user.email_verified:
            return render_template("auth/login.html",
                                   error="Please verify your email before logging in.",
                                   show_resend=True, email=email)

        # 2FA check
        if user.two_factor_enabled:
            session["2fa_user_id"] = user.id
            return redirect(url_for("auth.verify_2fa"))

        # Issue tokens
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        access_token = generate_access_token(user.id, user.role)
        refresh_token = generate_refresh_token(user.id)

        resp = make_response(redirect("/dashboard"))
        _set_auth_cookies(resp, access_token, refresh_token)
        return resp

    return render_template("auth/login.html")


# ─────────────────────────────────────────────────────────────────────────────
# Two-Factor Auth — Verify
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/2fa/verify", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = db.session.get(User, user_id)
        if not user or not user.two_factor_secret:
            session.pop("2fa_user_id", None)
            return redirect(url_for("auth.login"))

        totp = pyotp.TOTP(user.two_factor_secret)
        if not totp.verify(code, valid_window=1):
            return render_template("auth/2fa_verify.html",
                                   error="Invalid or expired code.")

        session.pop("2fa_user_id", None)
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        access_token = generate_access_token(user.id, user.role)
        refresh_token = generate_refresh_token(user.id)

        resp = make_response(redirect("/dashboard"))
        _set_auth_cookies(resp, access_token, refresh_token)
        return resp

    return render_template("auth/2fa_verify.html")


# ─────────────────────────────────────────────────────────────────────────────
# Two-Factor Auth — Setup
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = get_current_user()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("pending_2fa_secret")
        if not secret:
            return redirect(url_for("auth.setup_2fa"))

        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            return render_template("auth/2fa_setup.html",
                                   error="Invalid code. Try again.",
                                   qr_code=session.get("pending_2fa_qr"))

        user.two_factor_secret = secret
        user.two_factor_enabled = True
        db.session.commit()
        session.pop("pending_2fa_secret", None)
        session.pop("pending_2fa_qr", None)
        return render_template("auth/2fa_setup.html", success=True)

    # Generate new secret
    secret = pyotp.random_base32()
    session["pending_2fa_secret"] = secret

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email, issuer_name="MulikaScans"
    )

    # Generate QR code as base64
    qr = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode()
    session["pending_2fa_qr"] = qr_b64

    return render_template("auth/2fa_setup.html", qr_code=qr_b64, secret=secret)


@auth_bp.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    user = get_current_user()
    user.two_factor_secret = None
    user.two_factor_enabled = False
    db.session.commit()
    return redirect("/dashboard")


# ─────────────────────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect("/"))
    _clear_auth_cookies(resp)
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Token Refresh
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/refresh", methods=["POST"])
def refresh_token():
    token = request.cookies.get("refresh_token")
    if not token:
        return jsonify({"error": "Refresh token required"}), 401

    payload = decode_token(token)
    if not payload or payload.get("type") != "refresh":
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    user = db.session.get(User, payload["sub"])
    if not user:
        return jsonify({"error": "User not found"}), 401

    access_token = generate_access_token(user.id, user.role)
    resp = jsonify({"message": "Token refreshed"})
    is_prod = os.environ.get("FLASK_ENV") == "production"
    resp.set_cookie(
        "access_token", access_token, httponly=True, secure=is_prod, samesite="Lax",
        max_age=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 900))
    )
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Password Reset — Request
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            user.reset_token = secrets.token_urlsafe(32)
            user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
            db.session.commit()
            send_password_reset_email(user)
        # Always return success to prevent email enumeration
        return render_template("auth/forgot_password.html", sent=True, email=email)
    return render_template("auth/forgot_password.html")


# ─────────────────────────────────────────────────────────────────────────────
# Password Reset — Confirm
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_token_expiry:
        return render_template("auth/reset_password.html", invalid=True)

    if datetime.now(timezone.utc) > user.reset_token_expiry:
        return render_template("auth/reset_password.html", expired=True)

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if password != confirm:
            return render_template("auth/reset_password.html",
                                   token=token, error="Passwords do not match.")

        valid, err = validate_password(password)
        if not valid:
            return render_template("auth/reset_password.html",
                                   token=token, error=err)

        user.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        return render_template("auth/reset_password.html", success=True)

    return render_template("auth/reset_password.html", token=token)


# ─────────────────────────────────────────────────────────────────────────────
# Google OAuth2 — Skeleton (Authlib)
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/oauth/google")
def oauth_google():
    # TODO: Configure Authlib Google OAuth2
    # from authlib.integrations.flask_client import OAuth
    # oauth = OAuth(current_app)
    # google = oauth.register('google', ...)
    # return google.authorize_redirect(url_for('auth.oauth_google_callback', _external=True))
    return render_template("auth/login.html",
                           error="Google OAuth is coming soon. Please use email login.")


@auth_bp.route("/oauth/google/callback")
def oauth_google_callback():
    # TODO: Handle Google OAuth callback
    # token = google.authorize_access_token()
    # user_info = token.get('userinfo')
    # ...
    return redirect("/dashboard")


# ─────────────────────────────────────────────────────────────────────────────
# API: Current User Info
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/me")
@login_required
def me():
    user = get_current_user()
    limits = user.get_plan_limits()
    return jsonify({
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role,
        "email_verified": user.email_verified,
        "two_factor_enabled": user.two_factor_enabled,
        "scan_count_this_month": user.scan_count_this_month,
        "monthly_scan_limit": limits["scans"],
        "subscription_status": user.subscription_status,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    })
