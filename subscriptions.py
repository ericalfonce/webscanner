"""
MulikaScans — Subscription Middleware & Scan Limit Enforcement
"""

from functools import wraps
from flask import jsonify, redirect, request
from models import db, User
from auth import get_current_user


PLAN_SCAN_LIMITS = {
    "free":       2,
    "basic":      5,
    "pro":        20,
    "enterprise": 9999,
    "admin":      9999,
}

PLAN_ALLOWED_TYPES = {
    "free":       ["quick"],
    "basic":      ["quick", "full"],
    "pro":        ["quick", "full", "api", "compliance"],
    "enterprise": ["quick", "full", "api", "compliance"],
    "admin":      ["quick", "full", "api", "compliance"],
}

PLAN_PAGE_LIMITS = {
    "free":       10,
    "basic":      50,
    "pro":        200,
    "enterprise": 9999,
    "admin":      9999,
}


def check_scan_allowed(user: User, scan_type: str = "quick") -> tuple[bool, str | None]:
    """Return (allowed, error_message). Call before starting any scan."""
    role = user.role

    # Check scan type permission
    allowed_types = PLAN_ALLOWED_TYPES.get(role, ["quick"])
    if scan_type not in allowed_types:
        return False, (
            f"'{scan_type}' scans are not available on the {role.title()} plan. "
            f"Upgrade to access this scan type."
        )

    # Check monthly limit
    limit = PLAN_SCAN_LIMITS.get(role, 2)
    if user.scan_count_this_month >= limit:
        return False, (
            f"You have used all {limit} scans for this month on the {role.title()} plan. "
            f"Upgrade your plan or wait until next month."
        )

    return True, None


def increment_scan_count(user: User):
    """Increment the user's monthly scan counter."""
    user.scan_count_this_month = (user.scan_count_this_month or 0) + 1
    db.session.commit()


def get_page_limit(user: User) -> int:
    return PLAN_PAGE_LIMITS.get(user.role, 10)


# ─────────────────────────────────────────────────────────────────────────────
# Decorator: enforce scan limits on a route
# ─────────────────────────────────────────────────────────────────────────────
def require_scan_quota(scan_type_param: str = "scan_type"):
    """
    Decorator that checks scan quota before executing.
    Reads scan_type from JSON body or form.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.is_json:
                    return jsonify({"error": "Authentication required"}), 401
                return redirect("/login")

            data = request.get_json(silent=True) or {}
            scan_type = data.get(scan_type_param) or request.form.get(scan_type_param, "quick")

            allowed, err = check_scan_allowed(user, scan_type)
            if not allowed:
                if request.is_json:
                    return jsonify({
                        "error": err,
                        "upgrade_url": "/pricing",
                        "current_plan": user.role,
                        "scans_used": user.scan_count_this_month,
                        "scan_limit": PLAN_SCAN_LIMITS.get(user.role, 2),
                    }), 402
                return redirect("/pricing")

            return f(*args, **kwargs)
        return decorated
    return decorator
