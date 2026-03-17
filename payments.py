"""
MulikaScans — Flutterwave Payment Integration
Checkout sessions, webhook handler, billing dashboard.
Mobile money (M-Pesa, Airtel, Tigo) + card payments for Tanzania & East Africa.
"""

import os
from datetime import datetime, timezone
from flask import (Blueprint, request, jsonify, redirect,
                   render_template, current_app)

from models import db, User, Subscription, Payment
from auth import login_required, get_current_user
from flutterwave_service import (
    PLAN_CONFIG, PaymentError,
    create_subscription_checkout, verify_transaction,
    cancel_flw_subscription, get_payment_history,
    get_user_flw_subscriptions, parse_payment_method,
    extract_meta, validate_amount,
)

payments_bp = Blueprint("payments", __name__)


# ─────────────────────────────────────────────────────────────────────────────
# Pricing Page
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/pricing")
def pricing():
    user = get_current_user()
    return render_template("pricing.html", user=user)


# ─────────────────────────────────────────────────────────────────────────────
# Create Checkout — redirects to Flutterwave hosted page
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/v1/subscriptions/checkout", methods=["POST"])
@login_required
def create_checkout():
    user = get_current_user()
    data = request.get_json() or {}
    plan = data.get("plan", "").lower().strip()
    billing_cycle = data.get("billing_cycle", "monthly").lower().strip()

    if plan == "enterprise":
        return jsonify({"redirect_url": "mailto:support@mulikascans.com?subject=Enterprise%20Enquiry"}), 200

    if plan not in ("basic", "pro"):
        return jsonify({"error": "Invalid plan. Choose 'basic' or 'pro'."}), 400

    if billing_cycle not in ("monthly", "annual"):
        billing_cycle = "monthly"

    try:
        checkout_url, tx_ref = create_subscription_checkout(user, plan, billing_cycle)
        return jsonify({"checkout_url": checkout_url, "tx_ref": tx_ref})
    except PaymentError as e:
        current_app.logger.warning(f"Checkout error for user {user.id}: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Unexpected checkout error: {e}")
        return jsonify({"error": "Payment service unavailable. Please try again."}), 503


# ─────────────────────────────────────────────────────────────────────────────
# Payment Callback — Flutterwave redirects here after payment
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/payment/callback")
@login_required
def payment_callback():
    tx_ref = request.args.get("tx_ref", "")
    transaction_id = request.args.get("transaction_id", "")
    status = request.args.get("status", "")

    if status == "cancelled":
        return redirect("/pricing?cancelled=1")

    if status != "successful" or not transaction_id:
        return render_template("payment/failed.html",
                               reason="Payment was not completed. No charge has been made.")

    # Server-side verification — CRITICAL: never trust client redirect params alone
    try:
        tx_data = verify_transaction(transaction_id)
    except Exception as e:
        current_app.logger.error(f"FLW verify error: {e}")
        tx_data = None

    if not tx_data:
        return render_template("payment/failed.html",
                               reason="We could not verify your payment. If charged, contact support@mulikascans.com with your reference.")

    user_id, plan, billing_cycle = extract_meta(tx_data)
    billing_cycle = billing_cycle or "monthly"

    if not user_id or not plan:
        current_app.logger.warning(f"FLW callback: missing meta in tx {transaction_id}")
        return render_template("payment/failed.html",
                               reason="Payment verified but subscription activation failed. Contact support.")

    if not validate_amount(tx_data, plan, billing_cycle):
        current_app.logger.warning(f"FLW callback: amount mismatch tx={transaction_id}")
        return render_template("payment/failed.html",
                               reason="Payment amount mismatch. Contact support@mulikascans.com.")

    if tx_data.get("status") == "pending":
        return render_template("payment/pending.html",
                               tx_ref=tx_ref, transaction_id=transaction_id)

    _activate_subscription(user_id, plan, billing_cycle, tx_data, tx_ref)
    cfg = PLAN_CONFIG.get(f"{plan}_{billing_cycle}", {})
    return render_template("billing_success.html",
                           plan=plan.title(), billing_cycle=billing_cycle,
                           amount=cfg.get("amount", 0), tx_ref=tx_ref)


# ─────────────────────────────────────────────────────────────────────────────
# Payment Status Polling (for mobile money pending state)
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/v1/payment/status/<transaction_id>")
@login_required
def payment_status(transaction_id):
    try:
        tx_data = verify_transaction(transaction_id)
    except Exception:
        return jsonify({"status": "error"}), 500

    if not tx_data:
        return jsonify({"status": "pending"})

    user_id, plan, billing_cycle = extract_meta(tx_data)
    if tx_data.get("status") == "successful" and user_id and plan:
        _activate_subscription(user_id, plan, billing_cycle or "monthly", tx_data,
                               tx_data.get("tx_ref", ""))
        return jsonify({"status": "successful", "redirect": "/billing/success"})

    return jsonify({"status": tx_data.get("status", "pending")})


# ─────────────────────────────────────────────────────────────────────────────
# Flutterwave Webhook Handler
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/webhooks/flutterwave", methods=["POST"])
def flutterwave_webhook():
    import hmac as _hmac
    secret_hash = os.environ.get("FLW_WEBHOOK_SECRET_HASH", "")
    if not secret_hash:
        current_app.logger.error(
            "FLW_WEBHOOK_SECRET_HASH is not configured — webhook rejected for safety"
        )
        return jsonify({"error": "Webhook not configured"}), 503

    signature = request.headers.get("verif-hash", "")
    # Constant-time comparison to prevent timing attacks
    if not _hmac.compare_digest(signature, secret_hash):
        current_app.logger.warning("Flutterwave webhook: invalid verif-hash from %s",
                                   request.remote_addr)
        return jsonify({"error": "Invalid signature"}), 401

    payload = request.get_json(force=True) or {}
    event = payload.get("event", "")
    data = payload.get("data", {})

    current_app.logger.info(f"FLW webhook: {event}")

    if event == "charge.completed":
        if data.get("status") == "successful":
            _handle_successful_charge(data)
        else:
            _handle_failed_charge(data)
    elif event == "subscription.cancelled":
        _handle_subscription_cancelled(data)

    return jsonify({"status": "ok"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Billing Dashboard
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/billing")
@login_required
def billing_dashboard():
    user = get_current_user()
    limits = user.get_plan_limits()

    local_payments = (
        Payment.query.filter_by(user_id=user.id)
        .order_by(Payment.created_at.desc())
        .limit(20).all()
    )

    flw_payments = []
    flw_subscriptions = []
    if os.environ.get("FLW_SECRET_KEY", "").startswith("FLWSECK"):
        try:
            flw_payments = get_payment_history(user.email)
            flw_subscriptions = get_user_flw_subscriptions(user.email)
        except Exception as e:
            current_app.logger.warning(f"FLW API fetch failed: {e}")

    active_sub = (Subscription.query
                  .filter_by(user_id=user.id, status="active")
                  .order_by(Subscription.created_at.desc()).first())

    return render_template(
        "billing.html",
        user=user, limits=limits,
        local_payments=local_payments,
        flw_payments=flw_payments,
        flw_subscriptions=flw_subscriptions,
        active_sub=active_sub,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Cancel Subscription
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/v1/subscriptions/cancel", methods=["POST"])
@login_required
def cancel_subscription():
    user = get_current_user()
    sub = Subscription.query.filter_by(user_id=user.id, status="active").first()
    if not sub:
        return jsonify({"error": "No active subscription found."}), 404

    cancelled_flw = False
    if sub.flw_subscription_id:
        try:
            cancelled_flw = cancel_flw_subscription(sub.flw_subscription_id)
        except Exception as e:
            current_app.logger.error(f"FLW cancel error: {e}")

    sub.status = "cancelled"
    sub.cancelled_at = datetime.now(timezone.utc)
    user.subscription_status = "cancelled"
    db.session.commit()

    return jsonify({
        "message": "Subscription cancelled. You retain access until the end of your billing period.",
        "flw_cancelled": cancelled_flw,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Billing Success redirect target
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/billing/success")
@login_required
def billing_success():
    return render_template("billing_success.html", plan=None, billing_cycle=None,
                           amount=None, tx_ref=request.args.get("tx_ref", ""))


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────
def _activate_subscription(user_id, plan, billing_cycle, tx_data, tx_ref):
    key = f"{plan}_{billing_cycle}"
    cfg = PLAN_CONFIG.get(key, {})
    user = db.session.get(User, user_id)
    if not user:
        return

    user.role = cfg.get("role", plan)
    user.monthly_scan_limit = cfg.get("scan_limit", 2)
    user.subscription_status = "active"
    user.scan_count_this_month = 0

    payment_method = parse_payment_method(tx_data)

    Subscription.query.filter_by(user_id=user_id, status="active").update({"status": "superseded"})
    sub = Subscription(user_id=user_id, plan=plan, billing_cycle=billing_cycle,
                       flw_subscription_id=str(tx_data.get("id", "")), status="active")
    db.session.add(sub)
    db.session.flush()

    amount_cents = int((tx_data.get("amount") or 0) * 100)
    payment = Payment(
        user_id=user_id, subscription_id=sub.id,
        flw_tx_ref=tx_ref, flw_transaction_id=str(tx_data.get("id", "")),
        payment_method=payment_method, amount_cents=amount_cents,
        currency=(tx_data.get("currency") or "USD").lower(), status="succeeded",
    )
    db.session.add(payment)
    db.session.commit()
    current_app.logger.info(f"Activated: user={user_id} plan={plan}/{billing_cycle}")


def _handle_successful_charge(data):
    meta = data.get("meta", {}) or {}
    try:
        user_id = int(meta.get("user_id", 0))
    except (TypeError, ValueError):
        return
    plan = meta.get("plan", "")
    billing_cycle = meta.get("billing_cycle", "monthly")
    if user_id and plan:
        _activate_subscription(user_id, plan, billing_cycle, data, data.get("tx_ref", ""))


def _handle_failed_charge(data):
    meta = data.get("meta", {}) or {}
    try:
        user_id = int(meta.get("user_id", 0))
    except (TypeError, ValueError):
        return
    if not user_id:
        return
    user = db.session.get(User, user_id)
    if user:
        user.subscription_status = "past_due"
    sub = Subscription.query.filter_by(user_id=user_id, status="active").first()
    if sub:
        sub.status = "past_due"
    amount_cents = int((data.get("amount") or 0) * 100)
    db.session.add(Payment(
        user_id=user_id, flw_tx_ref=data.get("tx_ref", ""),
        flw_transaction_id=str(data.get("id", "")),
        payment_method=parse_payment_method(data),
        amount_cents=amount_cents,
        currency=(data.get("currency") or "USD").lower(), status="failed",
    ))
    db.session.commit()


def _handle_subscription_cancelled(data):
    flw_sub_id = str(data.get("id", ""))
    sub = Subscription.query.filter_by(flw_subscription_id=flw_sub_id).first()
    if not sub:
        return
    sub.status = "cancelled"
    sub.cancelled_at = datetime.now(timezone.utc)
    user = db.session.get(User, sub.user_id)
    if user:
        user.role = "free"
        user.monthly_scan_limit = 2
        user.subscription_status = "cancelled"
        user.subscription_id = None
    db.session.commit()
