"""
MulikaScans — Main Application
Production-grade Flask app with JWT auth, Stripe payments,
modular scanner, and role-based access control.
"""

import os
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, jsonify, url_for, session
from flask_mail import Mail
from flask_migrate import Migrate

from models import db, User, Scan, Vulnerability, ScanSchedule
from auth import auth_bp, limiter, login_required, require_role, require_active_subscription, get_current_user
from payments import payments_bp
from scanner.scanner_engine import run_scan, severity_counts
from subscriptions import check_scan_allowed, increment_scan_count, get_page_limit


# ─────────────────────────────────────────────────────────────────────────────
# App Factory
# ─────────────────────────────────────────────────────────────────────────────
def create_app():
    app = Flask(__name__)

    # Config
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-mulikascans")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///database/scans.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

    # Mail config
    app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
    app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
    app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@mulikascans.com")

    # Initialise extensions
    db.init_app(app)
    Migrate(app, db)
    _mail.init_app(app)
    limiter.init_app(app)

    # Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(payments_bp)

    return app


_mail = Mail()
app = create_app()


# ─────────────────────────────────────────────────────────────────────────────
# Context Processor — inject current_user into all templates
# ─────────────────────────────────────────────────────────────────────────────
@app.context_processor
def inject_user():
    return {"current_user": get_current_user()}


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
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    limits = user.get_plan_limits()

    # Recent scans
    recent_scans = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    # Aggregate stats
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

    if request.method == "POST":
        target = (request.form.get("url") or "").strip()
        scan_type = request.form.get("scan_type", "quick")

        if not target:
            return render_template("index.html", error="Please enter a target URL.", user=user)

        # Enforce plan limits
        allowed, err = check_scan_allowed(user, scan_type)
        if not allowed:
            return render_template("index.html", error=err, upgrade=True, user=user)

        # Validate URL
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        max_pages = get_page_limit(user)

        # Create scan record
        scan_record = Scan(
            user_id=user.id,
            target_url=target,
            scan_type=scan_type,
            status="running",
            started_at=datetime.now(timezone.utc),
            scan_config={"max_pages": max_pages, "timeout": 8},
        )
        db.session.add(scan_record)
        db.session.commit()

        # Run scan (synchronous for now — move to Celery for production async)
        try:
            findings = run_scan(target, scan_type=scan_type, max_pages=max_pages)
            counts = severity_counts(findings)

            # Persist vulnerabilities
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

            # Update scan record
            completed = datetime.now(timezone.utc)
            duration = (completed - scan_record.started_at).total_seconds()
            scan_record.status = "completed"
            scan_record.completed_at = completed
            scan_record.duration_seconds = duration
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
            return render_template("index.html",
                                   error=f"Scan failed: {str(e)}", user=user)

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

    return render_template("index.html", user=user)


# ─────────────────────────────────────────────────────────────────────────────
# Scan History
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/scans")
@login_required
def scan_history():
    user = get_current_user()
    page = request.args.get("page", 1, type=int)
    scans = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=20, error_out=False)
    )
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

    max_pages = get_page_limit(user)

    scan_record = Scan(
        user_id=user.id,
        target_url=target,
        scan_type=scan_type,
        status="running",
        started_at=datetime.now(timezone.utc),
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
        scan_record.duration_seconds = (completed - scan_record.started_at).total_seconds()
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
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

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
def compliance():
    user = get_current_user()
    return render_template("compliance.html", user=user)


# ─────────────────────────────────────────────────────────────────────────────
# Support / Contact Expert
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/contact-expert", methods=["POST"])
def contact_expert():
    name = request.form.get("name")
    email = request.form.get("email")
    org = request.form.get("organization")
    category = request.form.get("category")
    priority = request.form.get("priority")
    message = request.form.get("message")
    target = request.form.get("target")
    score = request.form.get("score")

    ticket_id = "MS-" + str(uuid.uuid4())[:8].upper()

    sla_map = {
        "critical": "Security response team will contact you within 1 hour.",
        "high":     "Security specialist will contact you within 4 hours.",
        "medium":   "Consultation scheduled within 24 hours.",
    }
    sla = sla_map.get(priority or "", "Advisory review within 2 business days.")

    app.logger.info(
        f"Support ticket {ticket_id}: {name} <{email}> | {category} | {priority} | {target}"
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
# DB Init CLI command
# ─────────────────────────────────────────────────────────────────────────────
@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created.")


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
