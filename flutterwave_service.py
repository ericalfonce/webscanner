"""
MulikaScans — Flutterwave Payment Service
Handles checkout creation, transaction verification, subscription management.
MulikaScans never touches card/mobile money details — Flutterwave handles all of that.
"""

import os
import time
import requests
from datetime import datetime, timezone

FLW_BASE_URL = "https://api.flutterwave.com/v3"

PLAN_CONFIG = {
    "basic_monthly":  {"amount": 14,  "currency": "USD", "plan_id_env": "FLW_BASIC_MONTHLY_PLAN_ID",  "role": "basic",      "scan_limit": 15},
    "basic_annual":   {"amount": 140, "currency": "USD", "plan_id_env": "FLW_BASIC_ANNUAL_PLAN_ID",   "role": "basic",      "scan_limit": 15},
    "pro_monthly":    {"amount": 45,  "currency": "USD", "plan_id_env": "FLW_PRO_MONTHLY_PLAN_ID",    "role": "pro",        "scan_limit": 50},
    "pro_annual":     {"amount": 450, "currency": "USD", "plan_id_env": "FLW_PRO_ANNUAL_PLAN_ID",     "role": "pro",        "scan_limit": 50},
    "enterprise":     {"amount": None, "currency": "USD", "plan_id_env": None,                         "role": "enterprise", "scan_limit": -1},
}


class PaymentError(Exception):
    pass


def _secret_key():
    return os.environ.get("FLW_SECRET_KEY", "")


def _headers():
    return {
        "Authorization": f"Bearer {_secret_key()}",
        "Content-Type": "application/json",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Create Flutterwave Standard Checkout link
# ─────────────────────────────────────────────────────────────────────────────
def create_subscription_checkout(user, plan_name: str, billing_cycle: str = "monthly") -> str:
    """
    Create a Flutterwave hosted payment page for a subscription.
    Returns the payment link URL.
    """
    key = f"{plan_name}_{billing_cycle}" if plan_name != "enterprise" else "enterprise"
    config = PLAN_CONFIG.get(key)
    if not config:
        raise PaymentError(f"Unknown plan/cycle combination: {plan_name}/{billing_cycle}")
    if config["amount"] is None:
        raise PaymentError("Enterprise pricing is custom. Contact sales.")

    plan_id = os.environ.get(config["plan_id_env"], "") if config["plan_id_env"] else ""
    if not plan_id:
        raise PaymentError(
            f"Payment plan not configured for {plan_name}/{billing_cycle}. "
            "Create the plan in Flutterwave Dashboard and add the ID to .env"
        )

    tx_ref = f"MULIKA-{user.id}-{plan_name}-{billing_cycle}-{int(time.time())}"
    redirect_url = os.environ.get("PAYMENT_REDIRECT_URL", "http://localhost:5000/payment/callback")

    payload = {
        "tx_ref": tx_ref,
        "amount": config["amount"],
        "currency": config["currency"],
        "redirect_url": redirect_url,
        "payment_plan": plan_id,
        "customer": {
            "email": user.email,
            "name": user.username or user.email.split("@")[0],
        },
        "customizations": {
            "title": "MulikaScans",
            "description": f"{plan_name.title()} Plan — {billing_cycle.title()}",
            "logo": os.environ.get("FRONTEND_URL", "") + "/static/img/logo.png",
        },
        "meta": {
            "user_id": str(user.id),
            "plan": plan_name,
            "billing_cycle": billing_cycle,
        },
        "payment_options": (
            "card,mobilemoneyghana,mobilemoneyfranco,mobilemoneyuganda,"
            "mobilemoneyrwanda,mobilemoneyzambia,mobilemoneytanzania,mpesa,ussd"
        ),
    }

    resp = requests.post(f"{FLW_BASE_URL}/payments", json=payload, headers=_headers(), timeout=15)
    data = resp.json()

    if data.get("status") == "success":
        return data["data"]["link"], tx_ref
    raise PaymentError(data.get("message", "Failed to create Flutterwave checkout session"))


# ─────────────────────────────────────────────────────────────────────────────
# Verify a transaction (ALWAYS call server-side before activating)
# ─────────────────────────────────────────────────────────────────────────────
def verify_transaction(transaction_id: str) -> dict | None:
    """
    Verify transaction via Flutterwave API.
    Returns the transaction data dict on success, None on failure.
    CRITICAL: Always verify server-side — never trust client redirect params alone.
    """
    resp = requests.get(
        f"{FLW_BASE_URL}/transactions/{transaction_id}/verify",
        headers=_headers(),
        timeout=15,
    )
    data = resp.json()
    if data.get("status") == "success" and data["data"]["status"] == "successful":
        return data["data"]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Cancel a recurring subscription
# ─────────────────────────────────────────────────────────────────────────────
def cancel_flw_subscription(flw_subscription_id: str) -> bool:
    """Cancel a recurring Flutterwave payment plan subscription."""
    resp = requests.put(
        f"{FLW_BASE_URL}/subscriptions/{flw_subscription_id}/cancel",
        headers=_headers(),
        timeout=15,
    )
    data = resp.json()
    return data.get("status") == "success"


# ─────────────────────────────────────────────────────────────────────────────
# Get subscription list for a user
# ─────────────────────────────────────────────────────────────────────────────
def get_user_flw_subscriptions(email: str) -> list:
    resp = requests.get(
        f"{FLW_BASE_URL}/subscriptions",
        params={"email": email},
        headers=_headers(),
        timeout=15,
    )
    data = resp.json()
    if data.get("status") == "success":
        return data.get("data", [])
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Get payment/transaction history for a user
# ─────────────────────────────────────────────────────────────────────────────
def get_payment_history(email: str, limit: int = 20) -> list:
    resp = requests.get(
        f"{FLW_BASE_URL}/transactions",
        params={"customer_email": email, "page": 1, "per_page": limit},
        headers=_headers(),
        timeout=15,
    )
    data = resp.json()
    if data.get("status") == "success":
        return data.get("data", [])
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Parse payment method from Flutterwave transaction data
# ─────────────────────────────────────────────────────────────────────────────
def parse_payment_method(tx_data: dict) -> str:
    """Return a human-friendly payment method label from FLW transaction data."""
    method = (tx_data.get("payment_type") or "").lower()
    if "mpesa" in method or "mobilemoneytanzania" in method:
        return "M-Pesa"
    if "airtel" in method:
        return "Airtel Money"
    if "tigo" in method:
        return "Tigo Pesa"
    if "card" in method:
        card = tx_data.get("card", {})
        last4 = card.get("last_4digits", "****")
        return f"Card ••••{last4}"
    if "bank" in method or "banktransfer" in method:
        return "Bank Transfer"
    if "ussd" in method:
        return "USSD"
    return method.title() or "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Extract user_id, plan, billing_cycle from verified transaction
# ─────────────────────────────────────────────────────────────────────────────
def extract_meta(tx_data: dict) -> tuple[int | None, str | None, str | None]:
    meta = tx_data.get("meta", {})
    try:
        user_id = int(meta.get("user_id", 0)) or None
    except (ValueError, TypeError):
        user_id = None
    plan = meta.get("plan")
    billing_cycle = meta.get("billing_cycle", "monthly")
    return user_id, plan, billing_cycle


# ─────────────────────────────────────────────────────────────────────────────
# Validate expected amount for plan
# ─────────────────────────────────────────────────────────────────────────────
def validate_amount(tx_data: dict, plan: str, billing_cycle: str) -> bool:
    key = f"{plan}_{billing_cycle}"
    config = PLAN_CONFIG.get(key)
    if not config or config["amount"] is None:
        return False
    paid = tx_data.get("amount", 0)
    currency = tx_data.get("currency", "").upper()
    return currency == config["currency"] and paid >= config["amount"]
