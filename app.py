"""
MulikaScans — Main Application
Production-grade Flask app with JWT auth, Stripe payments,
modular scanner, and role-based access control.
"""

import os
import re
import csv
import io
import json
import uuid
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, jsonify, url_for, session
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, CSRFError

from models import db, User, Scan, Vulnerability, ScanSchedule
from auth import (auth_bp, limiter, login_required, require_role,
                  require_active_subscription, get_current_user, validate_password)
from payments import payments_bp
from admin import admin_bp
from scanner.scanner_engine import run_scan, severity_counts
from subscriptions import check_scan_allowed, increment_scan_count, get_page_limit, has_feature
from supabase_service import create_user_client
from supabase_auth.errors import AuthApiError


# ─────────────────────────────────────────────────────────────────────────────
# Extensions (defined before create_app so they are in scope when called)
# ─────────────────────────────────────────────────────────────────────────────
_mail = Mail()
_csrf = CSRFProtect()


# ─────────────────────────────────────────────────────────────────────────────
# App Factory
# ─────────────────────────────────────────────────────────────────────────────
def create_app():
    app = Flask(__name__)

    # Config
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-mulikascans")

    # Resolve SQLite path to absolute (avoids CWD-dependent failures)
    _db_url = os.environ.get("DATABASE_URL", "sqlite:///database/scans.db")
    if _db_url.startswith("sqlite:///") and not _db_url.startswith("sqlite:////"):
        _rel = _db_url[len("sqlite:///"):]
        _abs = os.path.join(os.path.dirname(os.path.abspath(__file__)), _rel)
        os.makedirs(os.path.dirname(_abs), exist_ok=True)
        _db_url = f"sqlite:///{_abs}"
    app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

    # Security: limit upload and request body size to 10 MB
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

    # Mail config
    app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
    app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
    app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@mulikascans.com")

    # SEO
    app.config["BING_VERIFICATION"] = os.environ.get("BING_VERIFICATION", "")

    # Initialise extensions
    db.init_app(app)
    Migrate(app, db)
    _mail.init_app(app)
    limiter.init_app(app)
    _csrf.init_app(app)

    # Exempt OAuth session endpoint — it is called from client-side JS
    # after a Supabase redirect and cannot carry a form CSRF token.
    from flask_wtf.csrf import CSRFProtect
    _csrf.exempt("auth.oauth_google_session")
    _csrf.exempt("auth.oauth_google_callback")

    # Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(payments_bp)
    app.register_blueprint(admin_bp)

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        return render_template("errors/403.html", reason=e.description), 403

    return app


app = create_app()


# ─────────────────────────────────────────────────────────────────────────────
# Security Helpers
# ─────────────────────────────────────────────────────────────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _is_safe_target(url: str) -> tuple:
    """Block SSRF: private IPs, localhost, non-HTTP schemes.
    Returns (is_safe: bool, reason: str).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL."

    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP/HTTPS targets are allowed."

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "Invalid URL — missing hostname."

    if host in ("localhost", "localhost.localdomain", "0.0.0.0"):
        return False, "Scanning localhost is not allowed."

    try:
        resolved_ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(resolved_ip)
        for net in _PRIVATE_NETWORKS:
            if ip_obj in net:
                return False, "Scanning private or internal network addresses is not allowed."
    except socket.gaierror:
        return False, f"Could not resolve hostname '{host}'."
    except ValueError:
        pass

    return True, ""


# Image magic-bytes signatures for upload validation
_IMAGE_MAGIC = {
    "jpg":  b"\xff\xd8\xff",
    "jpeg": b"\xff\xd8\xff",
    "png":  b"\x89PNG",
    "webp": b"RIFF",
    "gif":  b"GIF8",
}

def _validate_image_magic(file_stream, ext: str) -> bool:
    """Verify uploaded file matches expected magic bytes, then rewind stream."""
    header = file_stream.read(12)
    file_stream.seek(0)
    magic = _IMAGE_MAGIC.get(ext)
    if not magic:
        return False
    return header.startswith(magic)


# ─────────────────────────────────────────────────────────────────────────────
# Security Headers — added to every response
# ─────────────────────────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    # Prevent the browser from serving cached authenticated pages after logout.
    # Any response delivered while a session exists is marked no-store so the
    # browser never writes it to its history cache.
    if request.cookies.get("access_token") or session.get("_uid"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if os.environ.get("FLASK_ENV") == "production":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"
        )
    # Hardened CSP — inline styles/scripts allowed (templates use them heavily),
    # no unsafe-eval, explicit allowlists for all external resources.
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdnjs.cloudflare.com; "
        "font-src 'self' data: fonts.gstatic.com cdnjs.cloudflare.com; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' https://nfyspkcmkaigqmnqdwte.supabase.co https://accounts.google.com; "
        "frame-src https://accounts.google.com; "
        "frame-ancestors 'none';"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Inactivity Session Timeout
# ─────────────────────────────────────────────────────────────────────────────
_SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", 30))

@app.before_request
def enforce_session_timeout():
    """Expire inactive authenticated sessions server-side."""
    # Skip static assets and the endpoints that handle logout/keepalive themselves
    if request.path.startswith("/static"):
        return
    if request.path in ("/logout", "/api/auth/keepalive"):
        return

    # Only applies to authenticated sessions
    if not (request.cookies.get("access_token") or session.get("_uid")):
        return

    now = datetime.now(timezone.utc)
    last = session.get("last_activity")
    if last:
        try:
            last_dt = datetime.fromisoformat(last)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
            idle_secs = (now - last_dt).total_seconds()
            if idle_secs / 60 > _SESSION_TIMEOUT_MINUTES:
                session.clear()
                if request.is_json:
                    resp = jsonify({
                        "error": "Session expired due to inactivity.",
                        "redirect": "/login?timeout=1"
                    })
                    resp.status_code = 401
                    resp.delete_cookie("access_token")
                    resp.delete_cookie("refresh_token")
                    return resp
                resp = redirect(url_for("auth.login") + "?timeout=1")
                resp.delete_cookie("access_token")
                resp.delete_cookie("refresh_token")
                return resp
            if idle_secs < 60:
                return  # Updated within the last minute — skip session write
        except (ValueError, TypeError):
            pass

    session["last_activity"] = now.isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Context Processor — inject current_user into all templates
# ─────────────────────────────────────────────────────────────────────────────
@app.context_processor
def inject_user():
    return {
        "current_user": get_current_user(),
        "session_timeout_minutes": _SESSION_TIMEOUT_MINUTES,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SEO — robots.txt, sitemap.xml
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/robots.txt")
def robots_txt():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /dashboard",
        "Disallow: /scan",
        "Disallow: /scans",
        "Disallow: /api/",
        "Disallow: /profile",
        "Disallow: /export/",
        "Disallow: /admin",
        "Disallow: /logout",
        "",
        "Sitemap: https://mulikascans.com/sitemap.xml",
    ]
    return "\n".join(lines), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/sitemap.xml")
def sitemap_xml():
    from datetime import date
    today = date.today().isoformat()
    pages = [
        ("https://mulikascans.com/",                "1.0",  "weekly"),
        ("https://mulikascans.com/pricing",          "0.9",  "monthly"),
        ("https://mulikascans.com/pricing/basic",    "0.7",  "monthly"),
        ("https://mulikascans.com/pricing/pro",      "0.7",  "monthly"),
        ("https://mulikascans.com/pricing/enterprise", "0.7", "monthly"),
        ("https://mulikascans.com/privacy",          "0.4",  "yearly"),
        ("https://mulikascans.com/support",          "0.5",  "monthly"),
        ("https://mulikascans.com/contact",          "0.5",  "monthly"),
    ]
    urls = "\n".join(
        f"  <url><loc>{loc}</loc><lastmod>{today}</lastmod>"
        f"<changefreq>{freq}</changefreq><priority>{pri}</priority></url>"
        for loc, pri, freq in pages
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>"""
    return xml, 200, {"Content-Type": "application/xml; charset=utf-8"}


# IndexNow key verification file (Bing/Yandex fast-indexing protocol)
_INDEXNOW_KEY = os.environ.get("INDEXNOW_KEY", "67fb14cc542d47fdada4048b4c3eb428")

@app.route("/67fb14cc542d47fdada4048b4c3eb428.txt")
def indexnow_key_file():
    return _INDEXNOW_KEY, 200, {"Content-Type": "text/plain; charset=utf-8"}


# ─────────────────────────────────────────────────────────────────────────────
# Public Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("product.html")


@app.route("/landing")
def landing():
    return render_template("landing.html")


# ─────────────────────────────────────────────────────────────────────────────
# Pricing
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/pricing")
def pricing():
    return render_template("pricing.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")


# ─────────────────────────────────────────────────────────────────────────────
# Profile
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_IMAGE_EXTS = {"jpg", "jpeg", "png", "webp", "gif"}
AVATAR_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads", "avatars")
# Ensure the avatars directory exists at startup (avoids per-request makedirs)
os.makedirs(AVATAR_UPLOAD_DIR, exist_ok=True)

_PHONE_RE = re.compile(r"[\d\s\+\-\(\)]{0,20}")
_AVATAR_PATH_RE = re.compile(r"uploads/avatars/avatar_\d+\.\w{2,4}")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()
    success = None
    error = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "update_profile":
            username = request.form.get("username", "").strip()[:64]
            phone = request.form.get("phone_number", "").strip()[:20]
            if phone and not _PHONE_RE.fullmatch(phone):
                error = "Invalid phone number format."
            else:
                user.username = username or None
                user.phone_number = phone or None
                db.session.commit()
                success = "Profile updated successfully."

        elif action == "upload_picture":
            file = request.files.get("picture")
            if not file or not file.filename:
                error = "No file selected."
            else:
                ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
                if ext not in ALLOWED_IMAGE_EXTS:
                    error = "Only JPG, PNG, WEBP, or GIF files are allowed."
                elif not _validate_image_magic(file.stream, ext):
                    error = "File content does not match the expected image format."
                else:
                    filename = f"avatar_{user.id}.{ext}"
                    file.save(os.path.join(AVATAR_UPLOAD_DIR, filename))
                    user.profile_picture = f"uploads/avatars/{filename}"
                    db.session.commit()
                    success = "Profile picture updated."

        elif action == "remove_picture":
            pic = user.profile_picture or ""
            if pic and not pic.startswith("http") and _AVATAR_PATH_RE.fullmatch(pic):
                try:
                    os.remove(os.path.join(AVATAR_UPLOAD_DIR, os.path.basename(pic)))
                except FileNotFoundError:
                    pass
            user.profile_picture = None
            db.session.commit()
            success = "Profile picture removed."

        elif action == "change_password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")

            if new_pw != confirm_pw:
                error = "New passwords do not match."
            else:
                ok, msg = validate_password(new_pw)
                if not ok:
                    error = msg
                else:
                    try:
                        # Use a fresh per-request client to avoid session state races
                        _sb = create_user_client()
                        # Verify current password (raises AuthApiError if wrong)
                        _sb.auth.sign_in_with_password({"email": user.email, "password": current_pw})
                        # sign_in_with_password sets the session on _sb; update the password
                        _sb.auth.update_user({"password": new_pw})
                        success = "Password changed successfully."
                    except AuthApiError:
                        error = "Current password is incorrect."
                    except Exception as e:
                        app.logger.error(f"Password change error for user {user.id}: {e}")
                        error = "Password change failed. Please try again."

    total_scans = Scan.query.filter_by(user_id=user.id).count()
    return render_template("profile.html", user=user,
                           success=success, error=error,
                           total_scans=total_scans)


@app.route("/support")
def support():
    return render_template("support.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        # In production: send email / create ticket here
        return render_template("contact.html", sent=True)
    return render_template("contact.html")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()

    limits = user.get_plan_limits()
    recent_scans = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    total_scans = Scan.query.filter_by(user_id=user.id).count()
    total_vulns = (
        db.session.query(db.func.sum(Scan.total_vulnerabilities))
        .filter_by(user_id=user.id)
        .scalar() or 0
    )
    total_critical = (
        db.session.query(db.func.sum(Scan.critical_count))
        .filter_by(user_id=user.id)
        .scalar() or 0
    )

    return render_template(
        "dashboard.html",
        user=user,
        limits=limits,
        recent_scans=recent_scans,
        total_scans=total_scans,
        total_vulns=total_vulns,
        total_critical=total_critical,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Scan — Form and Execution
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    user = get_current_user()

    # Build quota context for template
    from subscriptions import PLAN_LIMITS
    _limits = PLAN_LIMITS.get(user.role, PLAN_LIMITS["free"])
    _limit_val = _limits["scans_per_month"]
    quota = {
        "used": user.scan_count_this_month or 0,
        "limit": _limit_val,
        "unlimited": _limit_val == -1,
        "remaining": max(0, _limit_val - (user.scan_count_this_month or 0)) if _limit_val != -1 else None,
        "exhausted": (_limit_val != -1 and (user.scan_count_this_month or 0) >= _limit_val),
    }

    if request.method == "POST":
        target = (request.form.get("url") or "").strip()
        scan_type = request.form.get("scan_type", "quick")

        if not target:
            return render_template("index.html", error="Please enter a target URL.", user=user, quota=quota)

        # Check plan quota before doing anything
        allowed, err = check_scan_allowed(user, scan_type)
        if not allowed:
            return render_template("index.html", error=err, upgrade=True, user=user, quota=quota)

        # Validate URL scheme
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        # SSRF protection — block private/internal addresses
        safe, ssrf_reason = _is_safe_target(target)
        if not safe:
            return render_template("index.html", error=ssrf_reason, user=user, quota=quota)

        max_pages = get_page_limit(user)

        # ── Authenticated scanning (Basic+ only) ──────────────────────────────
        auth_cookies = {}
        auth_headers = {}
        if has_feature(user, "authenticated_scanning"):
            raw_cookie = (request.form.get("auth_cookie") or "").strip()
            raw_header_name = (request.form.get("auth_header_name") or "").strip()
            raw_header_value = (request.form.get("auth_header_value") or "").strip()
            if raw_cookie:
                for part in raw_cookie.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        auth_cookies[k.strip()] = v.strip()
            if raw_header_name and raw_header_value:
                auth_headers[raw_header_name] = raw_header_value

        # Create scan record and persist results to DB
        scan_started_at = datetime.now(timezone.utc)  # keep local ref — SQLite strips tz on reload
        scan_record = Scan(
            user_id=user.id,
            target_url=target,
            scan_type=scan_type,
            status="running",
            started_at=scan_started_at,
            scan_config={"max_pages": max_pages, "timeout": 8,
                         "authenticated": bool(auth_cookies or auth_headers)},
        )
        db.session.add(scan_record)
        db.session.commit()

        try:
            findings = run_scan(target, scan_type=scan_type, max_pages=max_pages,
                                auth_cookies=auth_cookies or None,
                                auth_headers=auth_headers or None)
            counts = severity_counts(findings)

            for f in findings:
                vuln = Vulnerability(
                    scan_id=scan_record.id,
                    name=f.get("name", f.get("type", "Unknown")),
                    description=f.get("detail", ""),
                    severity=f.get("severity", "info").capitalize(),
                    cvss_score=f.get("cvss_score"),
                    cvss_vector=f.get("cvss_vector"),
                    category=f.get("category"),
                    url_affected=f.get("url_affected", f.get("url")),
                    parameter=f.get("parameter"),
                    evidence=f.get("evidence"),
                    request_data=f.get("request_data"),
                    response_data=f.get("response_data"),
                    remediation=f.get("remediation"),
                    references=f.get("references"),
                    cwe_id=f.get("cwe_id"),
                    owasp_category=f.get("owasp_category"),
                )
                db.session.add(vuln)

            completed = datetime.now(timezone.utc)
            scan_record.status = "completed"
            scan_record.completed_at = completed
            scan_record.duration_seconds = (completed - scan_started_at).total_seconds()
            scan_record.total_vulnerabilities = len(findings)
            scan_record.critical_count = counts["critical"]
            scan_record.high_count = counts["high"]
            scan_record.medium_count = counts["medium"]
            scan_record.low_count = counts["low"]
            scan_record.info_count = counts["info"]
            scan_record.progress_percentage = 100
            increment_scan_count(user)
            db.session.commit()

        except Exception as e:
            scan_record.status = "failed"
            db.session.commit()
            app.logger.error(f"Scan failed for {target}: {e}")
            return render_template("index.html", error=f"Scan failed: {str(e)}", user=user, quota=quota)

        return render_template(
            "results.html",
            target=target,
            results=findings,
            scan=scan_record,
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            critical=counts["critical"],
        )

    return render_template("index.html", user=user, quota=quota)


# ─────────────────────────────────────────────────────────────────────────────
# Scan History
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/scans")
@login_required
def scan_history():
    user = get_current_user()
    page = request.args.get("page", 1, type=int)
    scans = (Scan.query.filter_by(user_id=user.id)
             .order_by(Scan.created_at.desc())
             .paginate(page=page, per_page=20, error_out=False))
    return render_template("scan_history.html", scans=scans, user=user)


@app.route("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    user = get_current_user()
    scan_record = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    vulns = sorted(
        scan_record.vulnerabilities.all(),
        key=lambda v: _sev_order.get(v.severity, 5)
    )
    return render_template("scan_detail.html", scan=scan_record, vulns=vulns, user=user)


# ─────────────────────────────────────────────────────────────────────────────
# API — Scan endpoints
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@login_required
@require_role("pro", "enterprise", "admin")
@require_active_subscription
@limiter.limit("10 per hour")
def api_scan():
    """REST API endpoint for programmatic scanning (Pro+ plans only)."""
    user = get_current_user()
    data = request.get_json() or {}
    target = data.get("url", "").strip()
    scan_type = data.get("scan_type", "quick")

    if not target:
        return jsonify({"error": "url is required"}), 400

    allowed, err = check_scan_allowed(user, scan_type)
    if not allowed:
        return jsonify({"error": err, "upgrade_url": "/pricing"}), 402

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # SSRF protection
    safe, ssrf_reason = _is_safe_target(target)
    if not safe:
        return jsonify({"error": ssrf_reason}), 400

    max_pages = get_page_limit(user)

    api_scan_started_at = datetime.now(timezone.utc)  # keep local ref — SQLite strips tz on reload
    scan_record = Scan(
        user_id=user.id,
        target_url=target,
        scan_type=scan_type,
        status="running",
        started_at=api_scan_started_at,
        scan_config={"max_pages": max_pages, "timeout": 8},
    )
    db.session.add(scan_record)
    db.session.commit()

    try:
        findings = run_scan(target, scan_type=scan_type, max_pages=max_pages)
        counts = severity_counts(findings)

        for f in findings:
            vuln = Vulnerability(
                scan_id=scan_record.id,
                name=f.get("name", f.get("type", "Unknown")),
                description=f.get("detail", ""),
                severity=f.get("severity", "info").capitalize(),
                cvss_score=f.get("cvss_score"),
                category=f.get("category"),
                url_affected=f.get("url_affected", f.get("url")),
                parameter=f.get("parameter"),
                evidence=f.get("evidence"),
                remediation=f.get("remediation"),
                references=f.get("references"),
                cwe_id=f.get("cwe_id"),
                owasp_category=f.get("owasp_category"),
            )
            db.session.add(vuln)

        completed = datetime.now(timezone.utc)
        scan_record.status = "completed"
        scan_record.completed_at = completed
        scan_record.duration_seconds = (completed - api_scan_started_at).total_seconds()
        scan_record.total_vulnerabilities = len(findings)
        scan_record.critical_count = counts["critical"]
        scan_record.high_count = counts["high"]
        scan_record.medium_count = counts["medium"]
        scan_record.low_count = counts["low"]
        scan_record.info_count = counts["info"]
        scan_record.progress_percentage = 100
        increment_scan_count(user)
        db.session.commit()

    except Exception as e:
        scan_record.status = "failed"
        db.session.commit()
        app.logger.error(f"API scan failed for {target}: {e}")
        return jsonify({"error": "Scan failed due to an internal error. Please try again."}), 500

    return jsonify({
        "scan_id": scan_record.id,
        "target": target,
        "scan_type": scan_type,
        "status": "completed",
        "duration_seconds": scan_record.duration_seconds,
        "summary": counts,
        "total_vulnerabilities": len(findings),
        "vulnerabilities": [f for f in findings],
    })


@app.route("/api/scans")
@login_required
def api_list_scans():
    user = get_current_user()
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).limit(50).all()
    return jsonify([{
        "id": s.id,
        "target_url": s.target_url,
        "scan_type": s.scan_type,
        "status": s.status,
        "total_vulnerabilities": s.total_vulnerabilities,
        "critical_count": s.critical_count,
        "high_count": s.high_count,
        "security_score": s.security_score(),
        "created_at": s.created_at.isoformat() if s.created_at else None,
    } for s in scans])


@app.route("/api/scans/<int:scan_id>")
@login_required
def api_get_scan(scan_id):
    user = get_current_user()
    s = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    vulns = [v.to_dict() for v in s.vulnerabilities.all()]
    return jsonify({
        "id": s.id,
        "target_url": s.target_url,
        "scan_type": s.scan_type,
        "status": s.status,
        "security_score": s.security_score(),
        "total_vulnerabilities": s.total_vulnerabilities,
        "critical_count": s.critical_count,
        "high_count": s.high_count,
        "medium_count": s.medium_count,
        "low_count": s.low_count,
        "info_count": s.info_count,
        "duration_seconds": s.duration_seconds,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "vulnerabilities": vulns,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled Scans (Pro+ only)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/schedules", methods=["GET", "POST"])
@login_required
@require_role("pro", "enterprise", "admin")
@limiter.limit("30 per hour", methods=["POST"])
def api_schedules():
    user = get_current_user()

    if request.method == "POST":
        data = request.get_json() or {}
        schedule = ScanSchedule(
            user_id=user.id,
            target_url=data.get("target_url", ""),
            scan_type=data.get("scan_type", "quick"),
            cron_expression=data.get("cron_expression", "0 0 * * 1"),
            is_active=True,
        )
        db.session.add(schedule)
        db.session.commit()
        return jsonify({"id": schedule.id, "message": "Schedule created"}), 201

    schedules = ScanSchedule.query.filter_by(user_id=user.id).all()
    return jsonify([{
        "id": s.id,
        "target_url": s.target_url,
        "scan_type": s.scan_type,
        "cron_expression": s.cron_expression,
        "is_active": s.is_active,
        "last_run": s.last_run.isoformat() if s.last_run else None,
        "next_run": s.next_run.isoformat() if s.next_run else None,
    } for s in schedules])


# ─────────────────────────────────────────────────────────────────────────────
# SOC & Analytics Pages (require login)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/threats")
@login_required
def threats():
    user = get_current_user()
    return render_template("threats.html", user=user)


@app.route("/intelligence")
@login_required
def intelligence():
    user = get_current_user()
    return render_template("intelligence.html", user=user)


@app.route("/analytics")
@login_required
def analytics():
    user = get_current_user()
    return render_template("analytics.html", user=user)


@app.route("/incidents")
@login_required
def incidents():
    user = get_current_user()
    return render_template("incidents.html", user=user)


@app.route("/compliance")
@login_required
@require_role("pro", "enterprise", "admin")
def compliance():
    user = get_current_user()
    return render_template("compliance.html", user=user)


# ─────────────────────────────────────────────────────────────────────────────
# Support / Contact Expert
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/contact-expert", methods=["POST"])
def contact_expert():
    # Sanitise and length-limit all inputs
    ALLOWED_PRIORITIES = {"critical", "high", "medium", "low"}
    ALLOWED_CATEGORIES = {"vulnerability", "compliance", "incident", "general", "other"}

    name     = (request.form.get("name", "") or "")[:100].strip()
    email    = (request.form.get("email", "") or "")[:254].strip()
    category = (request.form.get("category", "") or "").lower().strip()
    priority = (request.form.get("priority", "") or "").lower().strip()
    target   = (request.form.get("target", "") or "")[:256].strip()
    score    = (request.form.get("score", "") or "")[:10].strip()

    # Whitelist category and priority to prevent injection / log poisoning
    if category not in ALLOWED_CATEGORIES:
        category = "general"
    if priority not in ALLOWED_PRIORITIES:
        priority = "low"

    ticket_id = "MS-" + str(uuid.uuid4())[:8].upper()

    sla_map = {
        "critical": "Security response team will contact you within 1 hour.",
        "high":     "Security specialist will contact you within 4 hours.",
        "medium":   "Consultation scheduled within 24 hours.",
    }
    sla = sla_map.get(priority, "Advisory review within 2 business days.")

    # Log only safe, sanitised values
    app.logger.info(
        "Support ticket %s: category=%s priority=%s", ticket_id, category, priority
    )

    return render_template(
        "support_confirmation.html",
        ticket_id=ticket_id,
        priority=priority,
        target=target,
        score=score,
        sla_message=sla,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Export Routes (plan-gated)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/export/json/<int:scan_id>")
@login_required
def export_json(scan_id):
    """JSON export — Basic+ only."""
    user = get_current_user()
    if not has_feature(user, "json_export"):
        return jsonify({"error": "JSON export requires a Basic plan or higher.", "upgrade_url": "/pricing"}), 402
    scan_record = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    vulns = [v.to_dict() for v in scan_record.vulnerabilities.all()]
    payload = {
        "scan_id": scan_record.id,
        "target_url": scan_record.target_url,
        "scan_type": scan_record.scan_type,
        "status": scan_record.status,
        "security_score": scan_record.security_score(),
        "started_at": scan_record.started_at.isoformat() if scan_record.started_at else None,
        "completed_at": scan_record.completed_at.isoformat() if scan_record.completed_at else None,
        "duration_seconds": scan_record.duration_seconds,
        "total_vulnerabilities": scan_record.total_vulnerabilities,
        "critical_count": scan_record.critical_count,
        "high_count": scan_record.high_count,
        "medium_count": scan_record.medium_count,
        "low_count": scan_record.low_count,
        "info_count": scan_record.info_count,
        "vulnerabilities": vulns,
    }
    response = app.response_class(
        response=json.dumps(payload, indent=2),
        status=200,
        mimetype="application/json",
    )
    response.headers["Content-Disposition"] = f'attachment; filename="mulikascans_{scan_id}.json"'
    return response


@app.route("/export/csv/<int:scan_id>")
@login_required
def export_csv(scan_id):
    """CSV export — Basic+ only."""
    user = get_current_user()
    if not has_feature(user, "csv_export"):
        return jsonify({"error": "CSV export requires a Basic plan or higher.", "upgrade_url": "/pricing"}), 402
    scan_record = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    vulns = scan_record.vulnerabilities.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Severity", "CVSS Score", "Category", "URL Affected", "Parameter", "Evidence", "CWE", "OWASP", "Remediation"])
    for v in vulns:
        writer.writerow([
            v.name, v.severity, v.cvss_score or "", v.category or "",
            v.url_affected or "", v.parameter or "", v.evidence or "",
            v.cwe_id or "", v.owasp_category or "", v.remediation or "",
        ])
    response = app.response_class(
        response=output.getvalue(),
        status=200,
        mimetype="text/csv",
    )
    response.headers["Content-Disposition"] = f'attachment; filename="mulikascans_{scan_id}.csv"'
    return response


@app.route("/export/html/<int:scan_id>")
@login_required
def export_html(scan_id):
    """HTML report export — Pro+ only."""
    user = get_current_user()
    if not has_feature(user, "html_export"):
        return jsonify({"error": "HTML export requires a Pro plan or higher.", "upgrade_url": "/pricing"}), 402
    scan_record = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    vulns = sorted(scan_record.vulnerabilities.all(), key=lambda v: _sev_order.get(v.severity, 5))
    html = render_template("scan_detail.html", scan=scan_record, vulns=vulns, user=user)
    response = app.response_class(response=html, status=200, mimetype="text/html")
    response.headers["Content-Disposition"] = f'attachment; filename="mulikascans_report_{scan_id}.html"'
    return response


@app.route("/export/pdf/<int:scan_id>")
@login_required
def export_pdf(scan_id):
    """PDF report export — Basic+ only."""
    user = get_current_user()
    if not has_feature(user, "pdf_export"):
        return jsonify({"error": "PDF export requires a Basic plan or higher.", "upgrade_url": "/pricing"}), 402

    scan_record = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    vulns = sorted(
        [v for v in scan_record.vulnerabilities.all() if not v.false_positive],
        key=lambda v: _sev_order.get(v.severity, 5)
    )

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    # Custom styles
    title_style   = ParagraphStyle("title",   parent=styles["Title"],  fontSize=22, spaceAfter=4, textColor=colors.HexColor("#0ea5e9"))
    h2_style      = ParagraphStyle("h2",      parent=styles["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=4, textColor=colors.HexColor("#1e293b"))
    body_style    = ParagraphStyle("body",    parent=styles["Normal"],  fontSize=9,  spaceAfter=4, leading=13, textColor=colors.HexColor("#334155"))
    meta_style    = ParagraphStyle("meta",    parent=styles["Normal"],  fontSize=8,  textColor=colors.HexColor("#64748b"), spaceAfter=2)
    label_style   = ParagraphStyle("label",   parent=styles["Normal"],  fontSize=8,  textColor=colors.HexColor("#64748b"), fontName="Helvetica-Bold")

    SEV_COLORS = {
        "Critical": colors.HexColor("#ef4444"),
        "High":     colors.HexColor("#f97316"),
        "Medium":   colors.HexColor("#eab308"),
        "Low":      colors.HexColor("#22c55e"),
        "Info":     colors.HexColor("#94a3b8"),
    }

    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Paragraph("MulikaScans Security Report", title_style))
    story.append(Paragraph(f"Target: {scan_record.target_url}", meta_style))
    story.append(Paragraph(
        f"Scan #{scan_record.id} &bull; {scan_record.scan_type.upper()} &bull; "
        f"Score: {scan_record.security_score()}/100 &bull; "
        f"{scan_record.started_at.strftime('%Y-%m-%d %H:%M UTC') if scan_record.started_at else ''}",
        meta_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))

    # ── Summary table ─────────────────────────────────────────────────────────
    story.append(Paragraph("Vulnerability Summary", h2_style))
    summary_data = [
        ["Severity", "Count"],
        ["Critical", str(scan_record.critical_count)],
        ["High",     str(scan_record.high_count)],
        ["Medium",   str(scan_record.medium_count)],
        ["Low",      str(scan_record.low_count)],
        ["Info",     str(scan_record.info_count)],
        ["Total",    str(scan_record.total_vulnerabilities)],
    ]
    tbl = Table(summary_data, colWidths=[5*cm, 3*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ALIGN",       (1, 0), (1, -1), "CENTER"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 16))

    # ── Findings ──────────────────────────────────────────────────────────────
    if vulns:
        story.append(Paragraph("Detailed Findings", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=8))

        for i, v in enumerate(vulns, 1):
            sev_color = SEV_COLORS.get(v.severity, colors.HexColor("#94a3b8"))
            sev_text  = f'<font color="#{"%02x%02x%02x" % (int(sev_color.red*255), int(sev_color.green*255), int(sev_color.blue*255))}">[{v.severity or "Info"}]</font>'

            story.append(Paragraph(
                f"{i}. {sev_text} <b>{v.name}</b>"
                + (f" — CVSS {v.cvss_score:.1f}" if v.cvss_score else "")
                + (f" — {v.cwe_id}" if v.cwe_id else ""),
                body_style
            ))
            if v.url_affected:
                story.append(Paragraph(f"URL: {v.url_affected}", meta_style))
            if v.parameter:
                story.append(Paragraph(f"Parameter: {v.parameter}", meta_style))
            if v.description:
                story.append(Paragraph(v.description[:600], body_style))
            if v.evidence:
                story.append(Paragraph(f"<b>Evidence:</b> {v.evidence[:200]}", meta_style))
            if v.remediation:
                story.append(Paragraph(f"<b>Remediation:</b> {v.remediation[:400]}", meta_style))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No vulnerabilities detected.", body_style))

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    story.append(Paragraph(
        f"Generated by MulikaScans on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. "
        "Only scan systems you own or have explicit authorisation to test.",
        ParagraphStyle("footer", parent=styles["Normal"], fontSize=7, textColor=colors.HexColor("#94a3b8"), spaceAfter=0)
    ))

    doc.build(story)
    buf.seek(0)
    response = app.response_class(response=buf.read(), status=200, mimetype="application/pdf")
    response.headers["Content-Disposition"] = f'attachment; filename="mulikascans_report_{scan_id}.pdf"'
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Management — False Positive / Status
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/vulns/<int:vuln_id>/status", methods=["POST"])
@login_required
def update_vuln_status(vuln_id):
    """
    Mark a vulnerability as false positive / accepted_risk / open.
    Body: {"status": "false_positive"|"accepted_risk"|"open"}
    """
    user = get_current_user()
    data = request.get_json() or {}
    new_status = data.get("status", "").strip()

    ALLOWED = {"false_positive", "accepted_risk", "open", "confirmed", "fixed"}
    if new_status not in ALLOWED:
        return jsonify({"error": f"Invalid status. Allowed: {', '.join(ALLOWED)}"}), 400

    # Look up the vuln and verify ownership via the scan
    from models import Vulnerability as _Vuln
    vuln = _Vuln.query.join(Scan).filter(
        _Vuln.id == vuln_id,
        Scan.user_id == user.id
    ).first_or_404()

    vuln.status = new_status
    vuln.false_positive = (new_status == "false_positive")
    db.session.commit()

    return jsonify({"ok": True, "vuln_id": vuln_id, "status": new_status,
                    "false_positive": vuln.false_positive})


# ─────────────────────────────────────────────────────────────────────────────
# OpenAPI / Swagger Import — extract endpoints for scanning
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/swagger-parse", methods=["POST"])
@login_required
def swagger_parse():
    """
    Parse an uploaded OpenAPI/Swagger spec (JSON or YAML) and return
    a list of endpoint URLs to scan. Accepts multipart file upload
    or a JSON body with {"spec_url": "..."} to fetch remotely.

    Returns: {"base_url": str, "endpoints": [str, ...], "count": int}
    """
    user = get_current_user()

    spec_data = None

    # Option A: file upload
    uploaded = request.files.get("spec_file")
    if uploaded and uploaded.filename:
        try:
            content = uploaded.read().decode("utf-8", errors="replace")
            if uploaded.filename.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    spec_data = yaml.safe_load(content)
                except ImportError:
                    return jsonify({"error": "YAML support requires PyYAML. Upload a JSON spec instead."}), 400
            else:
                spec_data = json.loads(content)
        except Exception as e:
            return jsonify({"error": f"Could not parse spec file: {e}"}), 400

    # Option B: URL to fetch
    if not spec_data:
        body = request.get_json() or {}
        spec_url = (body.get("spec_url") or request.form.get("spec_url") or "").strip()
        if spec_url:
            safe, reason = _is_safe_target(spec_url)
            if not safe:
                return jsonify({"error": reason}), 400
            try:
                import requests as _requests_lib
                r = _requests_lib.get(spec_url, timeout=10, headers={"User-Agent": "MulikaScans/1.0"})
                r.raise_for_status()
                spec_data = r.json()
            except Exception as e:
                return jsonify({"error": f"Could not fetch spec: {e}"}), 400

    if not spec_data:
        return jsonify({"error": "Provide spec_file (multipart) or spec_url (JSON body)."}), 400

    # ── Parse OpenAPI 2.x (Swagger) or 3.x ──────────────────────────────────
    endpoints = []
    base_url = ""

    try:
        # OpenAPI 3.x
        if "openapi" in spec_data:
            servers = spec_data.get("servers", [{}])
            base_url = (servers[0].get("url", "") if servers else "").rstrip("/")
            for path in spec_data.get("paths", {}):
                full = base_url + path if base_url else path
                endpoints.append(full)

        # Swagger 2.x
        elif "swagger" in spec_data:
            host     = spec_data.get("host", "")
            basepath = spec_data.get("basePath", "").rstrip("/")
            schemes  = spec_data.get("schemes", ["https"])
            scheme   = schemes[0] if schemes else "https"
            base_url = f"{scheme}://{host}{basepath}" if host else basepath
            for path in spec_data.get("paths", {}):
                full = base_url + path if base_url else path
                endpoints.append(full)
        else:
            return jsonify({"error": "Unrecognised spec format. Expected OpenAPI 2.x or 3.x."}), 400

    except Exception as e:
        return jsonify({"error": f"Spec parsing error: {e}"}), 400

    # Deduplicate and cap at 200 endpoints
    endpoints = list(dict.fromkeys(endpoints))[:200]

    return jsonify({
        "base_url": base_url,
        "endpoints": endpoints,
        "count": len(endpoints),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Pricing plan sub-pages
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/pricing/basic")
def pricing_basic():
    return render_template("basic.html")


@app.route("/pricing/pro")
def pricing_pro():
    return render_template("pro.html")


@app.route("/pricing/enterprise")
def pricing_enterprise():
    return render_template("enterprise.html")


# ─────────────────────────────────────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("errors/500.html"), 500


@app.errorhandler(429)
def rate_limited(e):
    if request.is_json:
        return jsonify({"error": "Too many requests. Please slow down."}), 429
    return render_template("errors/429.html"), 429


# ─────────────────────────────────────────────────────────────────────────────
# Session Keepalive — resets inactivity timer without a full page reload
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/auth/keepalive", methods=["POST"])
@login_required
def session_keepalive():
    session["last_activity"] = datetime.now(timezone.utc).isoformat()
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# DB Init CLI command
# ─────────────────────────────────────────────────────────────────────────────
@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created.")


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
