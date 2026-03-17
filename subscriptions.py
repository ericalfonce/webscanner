"""
MulikaScans — Subscription Middleware & Scan Limit Enforcement
"""

from functools import wraps
from flask import jsonify, redirect, request
from models import db, User
from auth import get_current_user


# ─────────────────────────────────────────────────────────────────────────────
# Detailed plan limits (matches pricing page and spec exactly)
# ─────────────────────────────────────────────────────────────────────────────
PLAN_LIMITS = {
    "free": {
        "scans_per_month": 2,
        "scan_types": ["quick"],
        "max_crawl_depth": 2,
        "max_pages": 10,
        "max_concurrent_scans": 1,
        "modules": ["header_scanner", "ssl_scanner", "info_disclosure"],
        "pdf_export": False,
        "json_export": False,
        "csv_export": False,
        "html_export": False,
        "api_access": False,
        "scheduled_scans": False,
        "scan_comparison": False,
        "custom_headers": False,
        "authenticated_scanning": False,
        "compliance_report": False,
        "vulnerability_retest": False,
        "priority_queue": False,
        "whitelabel_reports": False,
        "team_members": 0,
        "target_groups": 1,
        "saved_targets": 3,
        "scan_history_days": 30,
        "support_level": "community",
    },
    "basic": {
        "scans_per_month": 15,
        "scan_types": ["quick", "full"],
        "max_crawl_depth": 5,
        "max_pages": 100,
        "max_concurrent_scans": 2,
        "modules": [
            "header_scanner", "ssl_scanner", "info_disclosure",
            "xss_scanner", "sqli_scanner", "csrf_scanner",
            "cors_scanner", "clickjacking", "open_redirect",
        ],
        "pdf_export": True,
        "json_export": True,
        "csv_export": True,
        "html_export": False,
        "api_access": False,
        "scheduled_scans": False,
        "scan_comparison": True,
        "custom_headers": True,
        "authenticated_scanning": False,
        "compliance_report": False,
        "vulnerability_retest": True,
        "priority_queue": False,
        "whitelabel_reports": False,
        "team_members": 0,
        "target_groups": 5,
        "saved_targets": 20,
        "scan_history_days": 90,
        "support_level": "email",
    },
    "pro": {
        "scans_per_month": 50,
        "scan_types": ["quick", "full", "api", "compliance"],
        "max_crawl_depth": 10,
        "max_pages": 500,
        "max_concurrent_scans": 5,
        "modules": "ALL",
        "pdf_export": True,
        "json_export": True,
        "csv_export": True,
        "html_export": True,
        "api_access": True,
        "scheduled_scans": True,
        "scan_comparison": True,
        "custom_headers": True,
        "authenticated_scanning": True,
        "compliance_report": True,
        "vulnerability_retest": True,
        "priority_queue": True,
        "whitelabel_reports": False,
        "team_members": 5,
        "target_groups": 25,
        "saved_targets": 100,
        "scan_history_days": 365,
        "support_level": "priority",
    },
    "enterprise": {
        "scans_per_month": -1,
        "scan_types": ["quick", "full", "api", "compliance", "enterprise"],
        "max_crawl_depth": -1,
        "max_pages": -1,
        "max_concurrent_scans": 20,
        "modules": "ALL",
        "pdf_export": True,
        "json_export": True,
        "csv_export": True,
        "html_export": True,
        "api_access": True,
        "scheduled_scans": True,
        "scan_comparison": True,
        "custom_headers": True,
        "authenticated_scanning": True,
        "compliance_report": True,
        "vulnerability_retest": True,
        "priority_queue": True,
        "whitelabel_reports": True,
        "team_members": -1,
        "target_groups": -1,
        "saved_targets": -1,
        "scan_history_days": -1,
        "support_level": "dedicated",
    },
    "admin": {
        "scans_per_month": -1,
        "scan_types": ["quick", "full", "api", "compliance", "enterprise"],
        "max_crawl_depth": -1,
        "max_pages": -1,
        "max_concurrent_scans": 20,
        "modules": "ALL",
        "pdf_export": True,
        "json_export": True,
        "csv_export": True,
        "html_export": True,
        "api_access": True,
        "scheduled_scans": True,
        "scan_comparison": True,
        "custom_headers": True,
        "authenticated_scanning": True,
        "compliance_report": True,
        "vulnerability_retest": True,
        "priority_queue": True,
        "whitelabel_reports": True,
        "team_members": -1,
        "target_groups": -1,
        "saved_targets": -1,
        "scan_history_days": -1,
        "support_level": "dedicated",
    },
}

# Convenience aliases (used by existing code)
PLAN_SCAN_LIMITS = {role: limits["scans_per_month"] for role, limits in PLAN_LIMITS.items()}
PLAN_ALLOWED_TYPES = {role: limits["scan_types"] for role, limits in PLAN_LIMITS.items()}
PLAN_PAGE_LIMITS = {
    role: (limits["max_pages"] if limits["max_pages"] != -1 else 9999)
    for role, limits in PLAN_LIMITS.items()
}


def check_scan_allowed(user: User, scan_type: str = "quick") -> tuple[bool, str | None]:
    """Return (allowed, error_message). Call before starting any scan."""
    role = user.role
    limits = PLAN_LIMITS.get(role, PLAN_LIMITS["free"])

    # Check scan type permission
    allowed_types = limits["scan_types"]
    if scan_type not in allowed_types:
        return False, (
            f"'{scan_type}' scans are not available on the {role.title()} plan. "
            "Upgrade to access this scan type."
        )

    # Check monthly limit (-1 = unlimited)
    limit = limits["scans_per_month"]
    if limit != -1 and user.scan_count_this_month >= limit:
        return False, (
            f"You have used all {limit} scans for this month on the {role.title()} plan. "
            "Upgrade your plan or wait until next month."
        )

    return True, None


def increment_scan_count(user: User):
    """Increment the user's monthly scan counter."""
    user.scan_count_this_month = (user.scan_count_this_month or 0) + 1
    db.session.commit()


def get_page_limit(user: User) -> int:
    limits = PLAN_LIMITS.get(user.role, PLAN_LIMITS["free"])
    pages = limits["max_pages"]
    return 9999 if pages == -1 else pages


def has_feature(user: User, feature: str) -> bool:
    """Check if a user's plan includes a specific feature."""
    limits = PLAN_LIMITS.get(user.role, PLAN_LIMITS["free"])
    return bool(limits.get(feature, False))


# ─────────────────────────────────────────────────────────────────────────────
# Decorator: enforce scan limits on a route
# ─────────────────────────────────────────────────────────────────────────────
def require_scan_quota(scan_type_param: str = "scan_type"):
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
