"""
MulikaScans — Admin Blueprint
Full control panel: user management, scan oversight, platform stats.
Only accessible to users with role='admin'.
"""

from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, jsonify, flash, url_for
from models import db, User, Scan, Vulnerability, Subscription, Payment
from auth import login_required, get_current_user

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ─────────────────────────────────────────────────────────────────────────────
# Admin-only decorator
# ─────────────────────────────────────────────────────────────────────────────
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect("/login?next=" + request.path)
        if user.role != "admin":
            return render_template("admin/forbidden.html", user=user), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard — Overview
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route("/")
@admin_required
def dashboard():
    user = get_current_user()

    # User counts by role
    role_counts = {}
    for role in ("free", "basic", "pro", "enterprise", "admin"):
        role_counts[role] = User.query.filter_by(role=role).count()
    total_users = sum(role_counts.values())

    # Registrations in the past 7 days
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    new_users_week = User.query.filter(User.created_at >= week_ago).count()

    # Scans stats
    total_scans = Scan.query.count()
    month_ago = datetime.now(timezone.utc) - timedelta(days=30)
    scans_this_month = Scan.query.filter(Scan.created_at >= month_ago).count()
    failed_scans = Scan.query.filter_by(status="failed").count()

    # Revenue
    total_revenue_cents = db.session.query(
        db.func.sum(Payment.amount_cents)
    ).filter_by(status="succeeded").scalar() or 0
    total_revenue = total_revenue_cents / 100

    month_revenue_cents = db.session.query(
        db.func.sum(Payment.amount_cents)
    ).filter(
        Payment.status == "succeeded",
        Payment.created_at >= month_ago
    ).scalar() or 0
    month_revenue = month_revenue_cents / 100

    # Active subscriptions
    active_subs = Subscription.query.filter_by(status="active").count()

    # Recent signups (last 10)
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    # Recent scans (last 10 across all users)
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()

    return render_template(
        "admin/dashboard.html",
        user=user,
        role_counts=role_counts,
        total_users=total_users,
        new_users_week=new_users_week,
        total_scans=total_scans,
        scans_this_month=scans_this_month,
        failed_scans=failed_scans,
        total_revenue=total_revenue,
        month_revenue=month_revenue,
        active_subs=active_subs,
        recent_users=recent_users,
        recent_scans=recent_scans,
    )


# ─────────────────────────────────────────────────────────────────────────────
# User Management — List
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route("/users")
@admin_required
def users():
    user = get_current_user()
    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "").strip()
    role_filter = request.args.get("role", "")

    query = User.query
    if search:
        query = query.filter(
            db.or_(
                User.email.ilike(f"%{search}%"),
                User.username.ilike(f"%{search}%"),
            )
        )
    if role_filter:
        query = query.filter_by(role=role_filter)

    users_page = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )

    return render_template(
        "admin/users.html",
        user=user,
        users_page=users_page,
        search=search,
        role_filter=role_filter,
    )


# ─────────────────────────────────────────────────────────────────────────────
# User Detail
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route("/users/<int:uid>")
@admin_required
def user_detail(uid):
    admin = get_current_user()
    target = User.query.get_or_404(uid)

    scan_count = Scan.query.filter_by(user_id=uid).count()
    recent_scans = (
        Scan.query.filter_by(user_id=uid)
        .order_by(Scan.created_at.desc())
        .limit(10).all()
    )
    payments = (
        Payment.query.filter_by(user_id=uid)
        .order_by(Payment.created_at.desc())
        .limit(10).all()
    )
    active_sub = Subscription.query.filter_by(user_id=uid, status="active").first()

    success = request.args.get("success")
    error = request.args.get("error")

    return render_template(
        "admin/user_detail.html",
        user=admin,
        target=target,
        scan_count=scan_count,
        recent_scans=recent_scans,
        payments=payments,
        active_sub=active_sub,
        success=success,
        error=error,
    )


# ─────────────────────────────────────────────────────────────────────────────
# User Actions (POST)
# ─────────────────────────────────────────────────────────────────────────────
VALID_ROLES = ("free", "basic", "pro", "enterprise", "admin")

ROLE_SCAN_LIMITS = {
    "free": 2,
    "basic": 5,
    "pro": 50,
    "enterprise": 9999,
    "admin": 9999,
}


@admin_bp.route("/users/<int:uid>/action", methods=["POST"])
@admin_required
def user_action(uid):
    admin = get_current_user()
    target = User.query.get_or_404(uid)
    action = request.form.get("action", "")

    # Prevent admins from accidentally self-demoting (require a second admin)
    if uid == admin.id and action in ("change_role", "delete", "suspend"):
        return redirect(url_for("admin.user_detail", uid=uid, error="Cannot perform that action on your own account."))

    if action == "change_role":
        new_role = request.form.get("role", "").lower()
        if new_role not in VALID_ROLES:
            return redirect(url_for("admin.user_detail", uid=uid, error="Invalid role."))
        target.role = new_role
        target.monthly_scan_limit = ROLE_SCAN_LIMITS.get(new_role, 2)
        if new_role == "admin":
            target.email_verified = True
        db.session.commit()
        return redirect(url_for("admin.user_detail", uid=uid, success=f"Role changed to {new_role}."))

    elif action == "verify_email":
        target.email_verified = True
        target.verification_token = None
        db.session.commit()
        return redirect(url_for("admin.user_detail", uid=uid, success="Email marked as verified."))

    elif action == "unverify_email":
        target.email_verified = False
        db.session.commit()
        return redirect(url_for("admin.user_detail", uid=uid, success="Email verification revoked."))

    elif action == "reset_scans":
        target.scan_count_this_month = 0
        db.session.commit()
        return redirect(url_for("admin.user_detail", uid=uid, success="Monthly scan count reset to 0."))

    elif action == "disable_2fa":
        target.two_factor_secret = None
        target.two_factor_enabled = False
        db.session.commit()
        return redirect(url_for("admin.user_detail", uid=uid, success="2FA disabled for user."))

    elif action == "reset_password_token":
        import secrets
        target.reset_token = secrets.token_urlsafe(32)
        target.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        db.session.commit()
        reset_link = f"/reset-password/{target.reset_token}"
        return redirect(url_for("admin.user_detail", uid=uid, success=f"Reset link generated: {reset_link}"))

    elif action == "delete":
        # Hard delete — cascades to scans and vulnerabilities if FK set up
        email = target.email
        # Delete related data first
        Vulnerability.query.filter(
            Vulnerability.scan_id.in_(
                db.session.query(Scan.id).filter_by(user_id=uid)
            )
        ).delete(synchronize_session=False)
        Scan.query.filter_by(user_id=uid).delete()
        Payment.query.filter_by(user_id=uid).delete()
        Subscription.query.filter_by(user_id=uid).delete()
        db.session.delete(target)
        db.session.commit()
        return redirect(url_for("admin.users", success=f"User {email} deleted."))

    return redirect(url_for("admin.user_detail", uid=uid, error="Unknown action."))


# ─────────────────────────────────────────────────────────────────────────────
# All Scans — Overview
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route("/scans")
@admin_required
def all_scans():
    user = get_current_user()
    page = request.args.get("page", 1, type=int)
    status_filter = request.args.get("status", "")
    search = request.args.get("q", "").strip()

    query = Scan.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    if search:
        query = query.filter(Scan.target_url.ilike(f"%{search}%"))

    scans_page = query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=30, error_out=False
    )

    return render_template(
        "admin/scans.html",
        user=user,
        scans_page=scans_page,
        status_filter=status_filter,
        search=search,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Admin API — quick JSON endpoints
# ─────────────────────────────────────────────────────────────────────────────
@admin_bp.route("/api/stats")
@admin_required
def api_stats():
    total_users = User.query.count()
    total_scans = Scan.query.count()
    active_subs = Subscription.query.filter_by(status="active").count()
    total_revenue = (db.session.query(db.func.sum(Payment.amount_cents))
                     .filter_by(status="succeeded").scalar() or 0) / 100
    return jsonify({
        "total_users": total_users,
        "total_scans": total_scans,
        "active_subscriptions": active_subs,
        "total_revenue_usd": total_revenue,
    })
