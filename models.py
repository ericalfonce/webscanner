from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()


# ─────────────────────────────────────────────────────────────────────────────
# User
# ─────────────────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    supabase_uid = db.Column(db.String(255), unique=True, nullable=True, index=True)

    # Role: free | basic | pro | enterprise | admin
    role = db.Column(db.String(20), nullable=False, default="free")

    # Email verification
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(255), nullable=True)

    # Password reset
    reset_token = db.Column(db.String(255), nullable=True)
    reset_token_expiry = db.Column(db.DateTime(timezone=True), nullable=True)

    # Stripe
    stripe_customer_id = db.Column(db.String(255), nullable=True)
    subscription_id = db.Column(db.String(255), nullable=True)
    subscription_status = db.Column(db.String(50), nullable=True)  # active | cancelled | past_due | trialing

    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)

    # Scan usage limits
    scan_count_this_month = db.Column(db.Integer, default=0)
    monthly_scan_limit = db.Column(db.Integer, default=2)  # Free tier default

    # Profile extras
    phone_number = db.Column(db.String(30), nullable=True)
    profile_picture = db.Column(db.String(512), nullable=True)  # local path or Google avatar URL

    # Two-factor auth (TOTP)
    two_factor_secret = db.Column(db.String(64), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)

    # Relationships
    scans = db.relationship("Scan", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    subscriptions = db.relationship("Subscription", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    payments = db.relationship("Payment", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    scan_schedules = db.relationship("ScanSchedule", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.email}>"

    def get_plan_limits(self):
        limits = {
            "free":       {"scans": 2,   "scan_types": ["quick"],              "pages": 10, "pdf": False, "api": False},
            "basic":      {"scans": 5,   "scan_types": ["quick", "full"],      "pages": 50, "pdf": True,  "api": False},
            "pro":        {"scans": 20,  "scan_types": ["quick", "full", "api", "compliance"], "pages": 200, "pdf": True, "api": True},
            "enterprise": {"scans": 9999, "scan_types": ["quick", "full", "api", "compliance"], "pages": 9999, "pdf": True, "api": True},
            "admin":      {"scans": 9999, "scan_types": ["quick", "full", "api", "compliance"], "pages": 9999, "pdf": True, "api": True},
        }
        return limits.get(self.role, limits["free"])

    def can_scan(self, scan_type="quick"):
        limits = self.get_plan_limits()
        if self.scan_count_this_month >= limits["scans"]:
            return False, "Monthly scan limit reached. Please upgrade your plan."
        if scan_type not in limits["scan_types"]:
            return False, f"{scan_type.title()} scans require a higher plan. Please upgrade."
        return True, None


# ─────────────────────────────────────────────────────────────────────────────
# Scan
# ─────────────────────────────────────────────────────────────────────────────
class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    target_url = db.Column(db.String(2048), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False, default="quick")  # quick | full | api | compliance

    # Status: queued | running | completed | failed | cancelled
    status = db.Column(db.String(20), nullable=False, default="queued", index=True)

    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)

    # Vulnerability counts (denormalised for fast dashboard queries)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)

    scan_config = db.Column(db.JSON, nullable=True)  # e.g. {"max_pages": 50, "timeout": 10}
    progress_percentage = db.Column(db.Integer, default=0)
    report_pdf_path = db.Column(db.String(512), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    vulnerabilities = db.relationship("Vulnerability", backref="scan", lazy="dynamic",
                                      cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.id} [{self.target_url}] {self.status}>"

    def security_score(self):
        score = 100
        score -= self.critical_count * 30
        score -= self.high_count * 20
        score -= self.medium_count * 10
        score -= self.low_count * 3
        return max(0, score)


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability
# ─────────────────────────────────────────────────────────────────────────────
class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)

    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Severity: critical | high | medium | low | info
    severity = db.Column(db.String(20), nullable=False, default="info", index=True)

    cvss_score = db.Column(db.Float, nullable=True)
    cvss_vector = db.Column(db.String(255), nullable=True)

    # Category: xss | sqli | csrf | ssrf | headers | ssl | misconfig | auth | info_disclosure | open_redirect
    category = db.Column(db.String(50), nullable=True)

    url_affected = db.Column(db.String(2048), nullable=True)
    parameter = db.Column(db.String(255), nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    request_data = db.Column(db.Text, nullable=True)
    response_data = db.Column(db.Text, nullable=True)

    remediation = db.Column(db.Text, nullable=True)
    references = db.Column(db.JSON, nullable=True)  # List of reference URLs

    false_positive = db.Column(db.Boolean, default=False)
    # Status: open | confirmed | fixed | accepted_risk
    status = db.Column(db.String(30), nullable=False, default="open")

    cwe_id = db.Column(db.String(20), nullable=True)   # e.g. "CWE-79"
    owasp_category = db.Column(db.String(50), nullable=True)  # e.g. "A03:2021"

    discovered_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Vulnerability {self.name} [{self.severity}]>"

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "category": self.category,
            "url_affected": self.url_affected,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references or [],
            "false_positive": self.false_positive,
            "status": self.status,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Subscription
# ─────────────────────────────────────────────────────────────────────────────
class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Plan: free | basic | pro | enterprise
    plan = db.Column(db.String(20), nullable=False, default="free")

    stripe_subscription_id = db.Column(db.String(255), nullable=True, unique=True)
    stripe_customer_id = db.Column(db.String(255), nullable=True)
    flw_subscription_id = db.Column(db.String(255), nullable=True)  # Flutterwave plan subscription ID
    billing_cycle = db.Column(db.String(10), nullable=True, default="monthly")  # monthly | annual

    # Status: active | cancelled | past_due | trialing | incomplete
    status = db.Column(db.String(30), nullable=False, default="active")

    current_period_start = db.Column(db.DateTime(timezone=True), nullable=True)
    current_period_end = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    cancelled_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    payments = db.relationship("Payment", backref="subscription", lazy="dynamic")

    def __repr__(self):
        return f"<Subscription {self.plan} [{self.status}]>"


# ─────────────────────────────────────────────────────────────────────────────
# Payment
# ─────────────────────────────────────────────────────────────────────────────
class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subscription_id = db.Column(db.Integer, db.ForeignKey("subscriptions.id"), nullable=True)

    stripe_payment_intent_id = db.Column(db.String(255), nullable=True, unique=True)
    flw_tx_ref = db.Column(db.String(255), nullable=True)          # Flutterwave tx_ref
    flw_transaction_id = db.Column(db.String(255), nullable=True)  # Flutterwave transaction ID
    payment_method = db.Column(db.String(50), nullable=True)       # mpesa | airtel | tigo | card | bank
    amount_cents = db.Column(db.Integer, nullable=False)  # Amount in cents (USD)
    currency = db.Column(db.String(10), nullable=False, default="usd")

    # Status: succeeded | failed | refunded | pending
    status = db.Column(db.String(30), nullable=False, default="pending")

    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Payment ${self.amount_cents/100:.2f} [{self.status}]>"


# ─────────────────────────────────────────────────────────────────────────────
# ScanSchedule
# ─────────────────────────────────────────────────────────────────────────────
class ScanSchedule(db.Model):
    __tablename__ = "scan_schedules"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    target_url = db.Column(db.String(2048), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False, default="quick")

    cron_expression = db.Column(db.String(100), nullable=False)  # e.g. "0 0 * * 1" (every Monday midnight)
    is_active = db.Column(db.Boolean, default=True)

    last_run = db.Column(db.DateTime(timezone=True), nullable=True)
    next_run = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<ScanSchedule {self.target_url} [{self.cron_expression}]>"
