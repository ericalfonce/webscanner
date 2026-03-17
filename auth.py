"""
MulikaScans — Production Authentication System
Supabase Auth, 2FA (TOTP), rate limiting, RBAC decorators.
"""

import os
import re
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timezone
from functools import wraps

from flask import (Blueprint, render_template, request, redirect,
                   session, jsonify, url_for, current_app, make_response, g)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models import db, User, Subscription
from supabase_service import get_supabase
from supabase_auth.errors import AuthApiError

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
# Cookie Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _set_auth_cookies(response, access_token: str, refresh_token: str):
    """Store Supabase tokens in HttpOnly cookies."""
    is_prod = os.environ.get("FLASK_ENV") == "production"
    response.set_cookie(
        "access_token", access_token,
        httponly=True, secure=is_prod, samesite="Lax",
        max_age=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 3600))
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
def get_current_user():
    """Return the authenticated user for this request.

    Result is cached in Flask's ``g`` so that multiple callers within the
    same request context (decorators, context processor, route handler) share
    a single Supabase token-verification round-trip.
    """
    if hasattr(g, "_current_user_resolved"):
        return g._current_user  # type: ignore[attr-defined]

    user = _resolve_current_user()
    g._current_user = user
    g._current_user_resolved = True
    return user


def _resolve_current_user():
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if token:
        try:
            sb = get_supabase()
            sb_response = sb.auth.get_user(token)
            if sb_response and sb_response.user:
                sb_uid = sb_response.user.id
                user = User.query.filter_by(supabase_uid=sb_uid).first()
                if not user:
                    # Try matching by email (for users created before migration)
                    user = User.query.filter_by(email=sb_response.user.email).first()
                    if user:
                        user.supabase_uid = sb_uid
                        db.session.commit()
                if user:
                    return user
        except Exception:
            pass

    # Fallback to Flask session
    user_id = session.get("_uid")
    if user_id:
        return db.session.get(User, user_id)

    return None


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
            return redirect(url_for("auth.login", next=request.path))
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
        if not current_app.config.get("MAIL_USERNAME"):
            current_app.logger.warning(
                f"MAIL_USERNAME not set — skipping email to {recipients}"
            )
            return
        msg = MailMessage(subject, recipients=recipients, html=body_html)
        mail.send(msg)
        current_app.logger.info(f"Email sent: '{subject}' → {recipients}")
    except Exception as e:
        current_app.logger.error(f"Email send FAILED to {recipients}: {e}")


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

        if not email or "@" not in email:
            return render_template("auth/register.html", error="Invalid email address.")

        valid, err = validate_password(password)
        if not valid:
            return render_template("auth/register.html", error=err, email=email)

        if User.query.filter_by(email=email).first():
            return render_template("auth/register.html", error="An account with this email already exists.")

        if username and User.query.filter_by(username=username).first():
            return render_template("auth/register.html", error="Username already taken.", email=email)

        # Register with Supabase Auth
        frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5000")
        try:
            sb = get_supabase()
            sb_response = sb.auth.sign_up({
                "email": email,
                "password": password,
                "options": {"email_redirect_to": frontend_url + "/verify-email/success"}
            })
            sb_user = sb_response.user
        except AuthApiError as e:
            current_app.logger.error(f"Supabase sign_up error: {e}")
            return render_template("auth/register.html", error="Registration failed. Please try again.", email=email)

        if not sb_user:
            return render_template("auth/register.html", error="Registration failed. Please try again.", email=email)

        # Create our app User record linked to Supabase
        email_verified = sb_user.email_confirmed_at is not None
        user = User(
            email=email,
            username=username,
            password_hash=None,           # Supabase manages passwords
            supabase_uid=sb_user.id,
            role="free",
            email_verified=email_verified,
            monthly_scan_limit=2,
        )
        db.session.add(user)
        sub = Subscription(user=user, plan="free", status="active")
        db.session.add(sub)
        db.session.commit()

        # If Supabase already confirmed email (e.g. email confirm disabled in dashboard), auto-login
        if email_verified and sb_response.session:
            session.clear()
            session["_uid"] = user.id
            resp = make_response(redirect("/dashboard"))
            _set_auth_cookies(resp, sb_response.session.access_token, sb_response.session.refresh_token)
            return resp

        # Otherwise show "check your email" page
        return render_template("auth/register_success.html", email=email)

    return render_template("auth/register.html")


# ─────────────────────────────────────────────────────────────────────────────
# Email Verification
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/verify-email/success")
def verify_email_success():
    return render_template("auth/verify_email.html", success=True)


@auth_bp.route("/resend-verification", methods=["POST"])
@limiter.limit("3 per hour")
def resend_verification():
    email = request.form.get("email", "").strip().lower()
    try:
        sb = get_supabase()
        sb.auth.resend({"type": "signup", "email": email})
    except Exception as e:
        current_app.logger.warning(f"Supabase resend verification error for {email}: {e}")
    return render_template("auth/verify_email_notice.html", email=email, resent=True)


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("60 per 15 minutes")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            sb = get_supabase()
            sb_response = sb.auth.sign_in_with_password({"email": email, "password": password})
            sb_user = sb_response.user
            sb_session = sb_response.session
        except AuthApiError:
            return render_template("auth/login.html", error="Invalid email or password.")

        if not sb_user or not sb_session:
            return render_template("auth/login.html", error="Invalid email or password.")

        # Check email verification
        if not sb_user.email_confirmed_at:
            return render_template("auth/login.html",
                                   error="Please verify your email before logging in.",
                                   show_resend=True, email=email)

        # Look up (or create on first Supabase login) our app User
        user = User.query.filter_by(supabase_uid=sb_user.id).first()
        if not user:
            user = User.query.filter_by(email=email).first()
            if user:
                user.supabase_uid = sb_user.id
                db.session.commit()

        if not user:
            return render_template("auth/login.html", error="Account not found. Please register.")

        # 2FA check
        if user.two_factor_enabled:
            session["2fa_user_id"] = user.id
            session["supabase_access_token"] = sb_session.access_token
            session["supabase_refresh_token"] = sb_session.refresh_token
            return redirect(url_for("auth.verify_2fa"))

        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        session.clear()
        session["_uid"] = user.id

        next_url = request.args.get("next") or request.form.get("next") or "/dashboard"
        if not next_url.startswith("/") or "//" in next_url:
            next_url = "/dashboard"

        resp = make_response(redirect(next_url))
        _set_auth_cookies(resp, sb_session.access_token, sb_session.refresh_token)
        return resp

    return render_template("auth/login.html", next=request.args.get("next", ""))


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

        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        # Regenerate session to prevent session fixation attacks
        session.clear()
        session["_uid"] = user.id

        access_token = session.pop("supabase_access_token", None)
        refresh_token_val = session.pop("supabase_refresh_token", None)

        resp = make_response(redirect("/dashboard"))
        if access_token and refresh_token_val:
            _set_auth_cookies(resp, access_token, refresh_token_val)
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
    return redirect("/profile")


# ─────────────────────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
def logout():
    session.clear()  # clears _uid and any 2fa state
    resp = make_response(redirect("/"))
    _clear_auth_cookies(resp)
    # Ensure the browser does not cache this response or any page visited before logout
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Token Refresh
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/refresh", methods=["POST"])
def refresh_token():
    token = request.cookies.get("refresh_token")
    if not token:
        return jsonify({"error": "Refresh token required"}), 401

    try:
        sb = get_supabase()
        sb_response = sb.auth.refresh_session(token)
        if not sb_response or not sb_response.session:
            return jsonify({"error": "Invalid or expired refresh token"}), 401
        new_session = sb_response.session
    except Exception:
        return jsonify({"error": "Token refresh failed"}), 401

    is_prod = os.environ.get("FLASK_ENV") == "production"
    resp = jsonify({"message": "Token refreshed"})
    resp.set_cookie(
        "access_token", new_session.access_token,
        httponly=True, secure=is_prod, samesite="Lax",
        max_age=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 3600))
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
        frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5000")
        try:
            sb = get_supabase()
            sb.auth.reset_password_for_email(email, {"redirect_to": frontend_url + "/reset-password"})
        except Exception as e:
            current_app.logger.error(f"Supabase reset_password_for_email error: {e}")
        # Always return success to prevent email enumeration
        return render_template("auth/forgot_password.html", sent=True, email=email)
    return render_template("auth/forgot_password.html")


# ─────────────────────────────────────────────────────────────────────────────
# Password Reset — Confirm
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        access_token = request.form.get("recovery_access_token", "").strip()
        refresh_token_val = request.form.get("recovery_refresh_token", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not access_token:
            return render_template("auth/reset_password.html", invalid=True)

        if password != confirm:
            return render_template("auth/reset_password.html",
                                   token="supabase", error="Passwords do not match.")

        valid, err = validate_password(password)
        if not valid:
            return render_template("auth/reset_password.html", token="supabase", error=err)

        try:
            sb = get_supabase()
            sb.auth.set_session(access_token, refresh_token_val)
            sb.auth.update_user({"password": password})
        except Exception as e:
            current_app.logger.error(f"Supabase password reset error: {e}")
            return render_template("auth/reset_password.html", invalid=True)

        return render_template("auth/reset_password.html", success=True)

    return render_template("auth/reset_password.html", token="supabase")


# ─────────────────────────────────────────────────────────────────────────────
# Google OAuth — Supabase
# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/oauth/google")
def oauth_google():
    """Redirect the user to Google via Supabase OAuth.

    We construct the URL manually (without PKCE) so Supabase returns tokens
    in the hash fragment that the callback JS can read directly.
    """
    from urllib.parse import urlencode
    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5000")
    supabase_url = os.environ.get("SUPABASE_URL", "https://nfyspkcmkaigqmnqdwte.supabase.co")
    params = urlencode({
        "provider": "google",
        "redirect_to": frontend_url + "/oauth/google/callback",
    })
    return redirect(f"{supabase_url}/auth/v1/authorize?{params}")


@auth_bp.route("/oauth/google/callback")
def oauth_google_callback():
    """Landing page after Google auth.
    Supabase returns tokens in the URL hash fragment; JS reads them and
    POSTs them to /oauth/google/session for server-side cookie setup.
    """
    return render_template("auth/oauth_callback.html")


@auth_bp.route("/oauth/google/session", methods=["POST"])
def oauth_google_session():
    """Receive tokens from the OAuth callback JS, verify with Supabase,
    create/link our app User, set auth cookies, return redirect URL.
    """
    data = request.get_json(silent=True) or {}
    access_token = data.get("access_token", "").strip()
    refresh_token_val = data.get("refresh_token", "").strip()

    if not access_token:
        return jsonify({"error": "No access token provided"}), 400

    try:
        sb = get_supabase()
        sb_response = sb.auth.get_user(access_token)
        sb_user = sb_response.user if sb_response else None
    except Exception as e:
        current_app.logger.error(f"Google OAuth session verification error: {e}")
        return jsonify({"error": "Token verification failed"}), 401

    if not sb_user:
        return jsonify({"error": "Could not verify Google user"}), 401

    # Find or create local User record
    user = User.query.filter_by(supabase_uid=sb_user.id).first()
    if not user:
        user = User.query.filter_by(email=sb_user.email).first()
        if user:
            # Link existing account to Supabase
            user.supabase_uid = sb_user.id
        else:
            # Brand-new user via Google — create app record
            meta = sb_user.user_metadata or {}
            raw_name = meta.get("full_name") or meta.get("name") or ""
            username = re.sub(r"[^a-z0-9_]", "", raw_name.lower().replace(" ", "_"))[:30] or None
            if username and User.query.filter_by(username=username).first():
                username = None  # Skip if already taken

            user = User(
                email=sb_user.email,
                username=username,
                password_hash=None,
                supabase_uid=sb_user.id,
                role="free",
                email_verified=True,   # Google accounts are pre-verified
                monthly_scan_limit=2,
                profile_picture=meta.get("avatar_url"),
            )
            db.session.add(user)
            db.session.add(Subscription(user=user, plan="free", status="active"))

    user.last_login = datetime.now(timezone.utc)
    user.email_verified = True
    db.session.commit()

    session.clear()
    session["_uid"] = user.id

    resp = jsonify({"redirect": "/dashboard"})
    _set_auth_cookies(resp, access_token, refresh_token_val)
    return resp


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
