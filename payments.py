"""
MulikaScans — PesaPal Payment Integration
Checkout sessions, IPN webhook handler, billing dashboard.
Mobile money (M-Pesa, Airtel, Tigo) + card payments for East Africa.
"""

import os
from datetime import datetime, timezone
from flask import (Blueprint, request, jsonify, redirect,
                   render_template, current_app)

from models import db, User, Subscription, Payment
from auth import login_required, get_current_user
from pesapal_service import (
    PLAN_CONFIG, PaymentError,
    create_subscription_checkout, is_payment_completed,
    get_transaction_status, parse_payment_method,
    extract_plan_from_reference, validate_amount,
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
# Create Checkout — redirects to PesaPal hosted page
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
        redirect_url, merchant_ref, order_tracking_id = create_subscription_checkout(
            user, plan, billing_cycle
        )
        return jsonify({
            "checkout_url": redirect_url,
            "tx_ref": merchant_ref,
            "order_tracking_id": order_tracking_id,
        })
    except PaymentError as e:
        current_app.logger.warning(f"PesaPal checkout error for user {user.id}: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Unexpected checkout error: {e}")
        return jsonify({"error": "Payment service unavailable. Please try again."}), 503


# ─────────────────────────────────────────────────────────────────────────────
# Payment Callback — PesaPal redirects here after payment
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/payment/callback")
@login_required
def payment_callback():
    # PesaPal sends: OrderTrackingId, OrderMerchantReference, OrderNotificationType
    order_tracking_id = request.args.get("OrderTrackingId", "")
    merchant_ref = request.args.get("OrderMerchantReference", "")

    if not order_tracking_id:
        return render_template("payment/failed.html",
                               reason="Payment was not completed. No charge has been made.")

    # Server-side verification — CRITICAL: never trust client redirect params alone
    try:
        completed, tx_data = is_payment_completed(order_tracking_id)
    except Exception as e:
        current_app.logger.error(f"PesaPal verify error: {e}")
        completed, tx_data = False, None

    if tx_data is None:
        return render_template("payment/failed.html",
                               reason="We could not verify your payment. If charged, contact support@mulikascans.com with your reference.")

    status_desc = (tx_data.get("payment_status_description") or "").lower()

    if status_desc in ("failed", "invalid", "reversed"):
        return render_template("payment/failed.html",
                               reason="Your payment was not successful. No charge has been made.")

    if status_desc == "pending" or not completed:
        return render_template("payment/pending.html",
                               tx_ref=merchant_ref, transaction_id=order_tracking_id)

    # Payment completed — extract plan from our merchant reference
    ref = merchant_ref or tx_data.get("merchant_reference", "")
    user_id, plan, billing_cycle = extract_plan_from_reference(ref)
    billing_cycle = billing_cycle or "monthly"

    if not user_id or not plan:
        current_app.logger.warning(f"PesaPal callback: missing plan in ref={ref}")
        return render_template("payment/failed.html",
                               reason="Payment verified but subscription activation failed. Contact support.")

    if not validate_amount(tx_data, plan, billing_cycle):
        current_app.logger.warning(f"PesaPal callback: amount mismatch tracking={order_tracking_id}")
        return render_template("payment/failed.html",
                               reason="Payment amount mismatch. Contact support@mulikascans.com.")

    _activate_subscription(user_id, plan, billing_cycle, tx_data, ref, order_tracking_id)
    cfg = PLAN_CONFIG.get(f"{plan}_{billing_cycle}", {})
    return render_template("billing_success.html",
                           plan=plan.title(), billing_cycle=billing_cycle,
                           amount=cfg.get("amount", 0), tx_ref=ref)


# ─────────────────────────────────────────────────────────────────────────────
# Payment Status Polling (for mobile money pending state)
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/v1/payment/status/<order_tracking_id>")
@login_required
def payment_status(order_tracking_id):
    try:
        completed, tx_data = is_payment_completed(order_tracking_id)
    except Exception:
        return jsonify({"status": "error"}), 500

    if tx_data is None:
        return jsonify({"status": "pending"})

    if completed:
        ref = tx_data.get("merchant_reference", "")
        user_id, plan, billing_cycle = extract_plan_from_reference(ref)
        if user_id and plan:
            _activate_subscription(user_id, plan, billing_cycle or "monthly",
                                   tx_data, ref, order_tracking_id)
        return jsonify({"status": "successful", "redirect": "/billing/success"})

    status_desc = (tx_data.get("payment_status_description") or "pending").lower()
    return jsonify({"status": status_desc})


# ─────────────────────────────────────────────────────────────────────────────
# PesaPal IPN Webhook Handler
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/webhooks/pesapal", methods=["POST"])
def pesapal_webhook():
    payload = request.get_json(force=True) or {}
    order_tracking_id = payload.get("OrderTrackingId", "")
    merchant_ref = payload.get("OrderMerchantReference", "")

    current_app.logger.info(f"PesaPal IPN: tracking={order_tracking_id} ref={merchant_ref}")

    if not order_tracking_id:
        return jsonify({"status": "ok"}), 200

    # Verify status server-side
    try:
        completed, tx_data = is_payment_completed(order_tracking_id)
    except Exception as e:
        current_app.logger.error(f"PesaPal IPN verify error: {e}")
        return jsonify({"status": "ok"}), 200

    if completed and tx_data:
        ref = merchant_ref or tx_data.get("merchant_reference", "")
        user_id, plan, billing_cycle = extract_plan_from_reference(ref)
        if user_id and plan:
            _activate_subscription(user_id, plan, billing_cycle or "monthly",
                                   tx_data, ref, order_tracking_id)
    elif tx_data:
        status_desc = (tx_data.get("payment_status_description") or "").lower()
        if status_desc in ("failed", "reversed"):
            _handle_failed_payment(merchant_ref, tx_data)

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

    active_sub = (Subscription.query
                  .filter_by(user_id=user.id, status="active")
                  .order_by(Subscription.created_at.desc()).first())

    return render_template(
        "billing.html",
        user=user, limits=limits,
        local_payments=local_payments,
        flw_payments=[],          # kept for template compatibility
        flw_subscriptions=[],     # kept for template compatibility
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

    sub.status = "cancelled"
    sub.cancelled_at = datetime.now(timezone.utc)
    user.subscription_status = "cancelled"
    db.session.commit()

    return jsonify({
        "message": "Subscription cancelled. You retain access until the end of your billing period.",
    })


# ─────────────────────────────────────────────────────────────────────────────
# Admin: Register PesaPal IPN (run once after deployment, then add ID to .env)
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/admin/register-ipn")
@login_required
def admin_register_ipn():
    from auth import get_current_user as _gcr
    u = _gcr()
    if not u or u.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    try:
        from pesapal_service import register_ipn
        ipn_id = register_ipn()
        return jsonify({
            "ipn_id": ipn_id,
            "message": f"Add PESAPAL_IPN_ID={ipn_id} to your production .env then restart the app.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
def _activate_subscription(user_id, plan, billing_cycle, tx_data, merchant_ref, order_tracking_id):
    key = f"{plan}_{billing_cycle}"
    cfg = PLAN_CONFIG.get(key, {})
    user = db.session.get(User, user_id)
    if not user:
        return

    # Idempotency — don't activate twice for the same tracking ID
    existing = Payment.query.filter_by(flw_transaction_id=order_tracking_id,
                                       status="succeeded").first()
    if existing:
        return

    user.role = cfg.get("role", plan)
    user.monthly_scan_limit = cfg.get("scan_limit", 2)
    user.subscription_status = "active"
    user.scan_count_this_month = 0

    payment_method = parse_payment_method(tx_data)

    Subscription.query.filter_by(user_id=user_id, status="active").update({"status": "superseded"})
    sub = Subscription(
        user_id=user_id, plan=plan, billing_cycle=billing_cycle,
        flw_subscription_id=order_tracking_id,  # store PesaPal order_tracking_id
        status="active",
    )
    db.session.add(sub)
    db.session.flush()

    amount_cents = int(float(tx_data.get("amount") or 0) * 100)
    payment = Payment(
        user_id=user_id, subscription_id=sub.id,
        flw_tx_ref=merchant_ref,
        flw_transaction_id=order_tracking_id,
        payment_method=payment_method,
        amount_cents=amount_cents,
        currency=(tx_data.get("currency") or "USD").lower(),
        status="succeeded",
    )
    db.session.add(payment)
    db.session.commit()
    current_app.logger.info(f"Activated: user={user_id} plan={plan}/{billing_cycle}")


def _handle_failed_payment(merchant_ref, tx_data):
    user_id, plan, billing_cycle = extract_plan_from_reference(merchant_ref)
    if not user_id:
        return
    user = db.session.get(User, user_id)
    if user:
        user.subscription_status = "past_due"
    sub = Subscription.query.filter_by(user_id=user_id, status="active").first()
    if sub:
        sub.status = "past_due"
    amount_cents = int(float(tx_data.get("amount") or 0) * 100)
    db.session.add(Payment(
        user_id=user_id,
        flw_tx_ref=merchant_ref,
        flw_transaction_id=tx_data.get("order_tracking_id", ""),
        payment_method=parse_payment_method(tx_data),
        amount_cents=amount_cents,
        currency=(tx_data.get("currency") or "USD").lower(),
        status="failed",
    ))
    db.session.commit()
