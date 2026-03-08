"""
MulikaScans — Stripe Payment Integration
Checkout sessions, webhook handler, billing portal.
"""

import os
import stripe
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, redirect, url_for, render_template, current_app

from models import db, User, Subscription, Payment
from auth import login_required, get_current_user

payments_bp = Blueprint("payments", __name__)

# ─────────────────────────────────────────────────────────────────────────────
# Stripe client setup
# ─────────────────────────────────────────────────────────────────────────────
def _stripe():
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    return stripe


PLAN_CONFIG = {
    "basic": {
        "name": "Basic",
        "price_id": lambda: os.environ.get("STRIPE_BASIC_PRICE_ID", ""),
        "amount_cents": 2900,
        "currency": "usd",
        "scan_limit": 5,
        "role": "basic",
    },
    "pro": {
        "name": "Pro",
        "price_id": lambda: os.environ.get("STRIPE_PRO_PRICE_ID", ""),
        "amount_cents": 7900,
        "currency": "usd",
        "scan_limit": 20,
        "role": "pro",
    },
    "enterprise": {
        "name": "Enterprise",
        "price_id": None,
        "amount_cents": None,
        "currency": "usd",
        "scan_limit": 9999,
        "role": "enterprise",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Pricing Page
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/pricing")
def pricing():
    user = get_current_user()
    stripe_pk = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
    return render_template("pricing.html", user=user, stripe_pk=stripe_pk,
                           plans=PLAN_CONFIG)


# ─────────────────────────────────────────────────────────────────────────────
# Create Checkout Session
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/payments/create-checkout", methods=["POST"])
@login_required
def create_checkout_session():
    user = get_current_user()
    data = request.get_json() or {}
    plan = data.get("plan", "basic")

    if plan not in PLAN_CONFIG or plan == "enterprise":
        return jsonify({"error": "Invalid plan. Contact us for Enterprise pricing."}), 400

    cfg = PLAN_CONFIG[plan]
    price_id = cfg["price_id"]()
    if not price_id:
        return jsonify({"error": "Payment not configured. Contact support."}), 503

    s = _stripe()

    # Get or create Stripe customer
    customer_id = user.stripe_customer_id
    if not customer_id:
        customer = s.Customer.create(
            email=user.email,
            metadata={"user_id": user.id, "app": "MulikaScans"}
        )
        customer_id = customer.id
        user.stripe_customer_id = customer_id
        db.session.commit()

    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5000")

    session_obj = s.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{frontend_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{frontend_url}/pricing",
        metadata={"user_id": user.id, "plan": plan},
        subscription_data={
            "metadata": {"user_id": user.id, "plan": plan}
        },
    )

    return jsonify({"checkout_url": session_obj.url})


# ─────────────────────────────────────────────────────────────────────────────
# Stripe Webhook Handler
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/api/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

    s = _stripe()
    try:
        event = s.Webhook.construct_event(payload, sig_header, webhook_secret)
    except s.error.SignatureVerificationError:
        current_app.logger.warning("Stripe webhook signature verification failed")
        return jsonify({"error": "Invalid signature"}), 400
    except Exception as e:
        current_app.logger.error(f"Stripe webhook error: {e}")
        return jsonify({"error": "Webhook error"}), 400

    event_type = event["type"]
    data = event["data"]["object"]

    current_app.logger.info(f"Stripe webhook: {event_type}")

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(data)

    elif event_type == "invoice.paid":
        _handle_invoice_paid(data)

    elif event_type == "invoice.payment_failed":
        _handle_invoice_payment_failed(data)

    elif event_type == "customer.subscription.deleted":
        _handle_subscription_deleted(data)

    elif event_type == "customer.subscription.updated":
        _handle_subscription_updated(data)

    return jsonify({"received": True})


def _handle_checkout_completed(session_obj):
    user_id = int(session_obj.get("metadata", {}).get("user_id", 0))
    plan = session_obj.get("metadata", {}).get("plan", "basic")
    stripe_sub_id = session_obj.get("subscription")

    user = db.session.get(User, user_id)
    if not user:
        return

    cfg = PLAN_CONFIG.get(plan, PLAN_CONFIG["basic"])

    user.role = cfg["role"]
    user.monthly_scan_limit = cfg["scan_limit"]
    user.subscription_id = stripe_sub_id
    user.subscription_status = "active"

    # Create or update Subscription record
    sub = Subscription.query.filter_by(stripe_subscription_id=stripe_sub_id).first()
    if not sub:
        sub = Subscription(
            user_id=user_id,
            plan=plan,
            stripe_subscription_id=stripe_sub_id,
            stripe_customer_id=session_obj.get("customer"),
            status="active",
        )
        db.session.add(sub)

    db.session.commit()


def _handle_invoice_paid(invoice):
    stripe_sub_id = invoice.get("subscription")
    if not stripe_sub_id:
        return

    sub = Subscription.query.filter_by(stripe_subscription_id=stripe_sub_id).first()
    if not sub:
        return

    user = db.session.get(User, sub.user_id)
    if user:
        user.subscription_status = "active"
        user.scan_count_this_month = 0  # Reset monthly scan count on renewal

    # Record payment
    payment = Payment(
        user_id=sub.user_id,
        subscription_id=sub.id,
        stripe_payment_intent_id=invoice.get("payment_intent"),
        amount_cents=invoice.get("amount_paid", 0),
        currency=invoice.get("currency", "usd"),
        status="succeeded",
    )
    db.session.add(payment)
    db.session.commit()


def _handle_invoice_payment_failed(invoice):
    stripe_sub_id = invoice.get("subscription")
    if not stripe_sub_id:
        return

    sub = Subscription.query.filter_by(stripe_subscription_id=stripe_sub_id).first()
    if not sub:
        return

    user = db.session.get(User, sub.user_id)
    if user:
        user.subscription_status = "past_due"

    sub.status = "past_due"

    # Record failed payment
    payment = Payment(
        user_id=sub.user_id,
        subscription_id=sub.id,
        stripe_payment_intent_id=invoice.get("payment_intent"),
        amount_cents=invoice.get("amount_due", 0),
        currency=invoice.get("currency", "usd"),
        status="failed",
    )
    db.session.add(payment)
    db.session.commit()


def _handle_subscription_deleted(subscription):
    stripe_sub_id = subscription.get("id")
    sub = Subscription.query.filter_by(stripe_subscription_id=stripe_sub_id).first()
    if not sub:
        return

    user = db.session.get(User, sub.user_id)
    if user:
        user.role = "free"
        user.monthly_scan_limit = 2
        user.subscription_status = "cancelled"
        user.subscription_id = None

    sub.status = "cancelled"
    sub.cancelled_at = datetime.now(timezone.utc)
    db.session.commit()


def _handle_subscription_updated(subscription):
    stripe_sub_id = subscription.get("id")
    sub = Subscription.query.filter_by(stripe_subscription_id=stripe_sub_id).first()
    if not sub:
        return

    new_status = subscription.get("status", "active")
    sub.status = new_status

    user = db.session.get(User, sub.user_id)
    if user:
        user.subscription_status = new_status

    db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Billing Portal (Stripe Customer Portal)
# ─────────────────────────────────────────────────────────────────────────────
@payments_bp.route("/billing")
@login_required
def billing_portal():
    user = get_current_user()
    s = _stripe()

    if not user.stripe_customer_id:
        # Free user — redirect to pricing
        return redirect("/pricing")

    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5000")
    try:
        portal_session = s.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=f"{frontend_url}/dashboard",
        )
        return redirect(portal_session.url)
    except Exception as e:
        current_app.logger.error(f"Billing portal error: {e}")
        return render_template("billing.html", error="Unable to open billing portal. Please contact support.")


@payments_bp.route("/billing/success")
@login_required
def billing_success():
    session_id = request.args.get("session_id", "")
    return render_template("billing_success.html", session_id=session_id)
