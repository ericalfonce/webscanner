"""
MulikaScans — PesaPal v3 Payment Service
Handles checkout creation, transaction verification, IPN registration.
MulikaScans never touches card/mobile money details — PesaPal handles all of that.
"""

import os
import time
import requests
from datetime import datetime, timezone

PESAPAL_BASE_URL = "https://pay.pesapal.com/v3"

PLAN_CONFIG = {
    "basic_monthly":  {"amount": 14,   "currency": "USD", "role": "basic",      "scan_limit": 15},
    "basic_annual":   {"amount": 140,  "currency": "USD", "role": "basic",      "scan_limit": 15},
    "pro_monthly":    {"amount": 45,   "currency": "USD", "role": "pro",        "scan_limit": 50},
    "pro_annual":     {"amount": 450,  "currency": "USD", "role": "pro",        "scan_limit": 50},
    "enterprise":     {"amount": None, "currency": "USD", "role": "enterprise", "scan_limit": -1},
}

# In-process token cache (tokens are valid ~5 minutes)
_token_cache = {"token": None, "expires_at": 0.0}


class PaymentError(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Auth — get Bearer token
# ─────────────────────────────────────────────────────────────────────────────
def _get_token() -> str:
    """Fetch a PesaPal Bearer token, using cached value if still valid."""
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 30:
        return _token_cache["token"]

    consumer_key = os.environ.get("PESAPAL_CONSUMER_KEY", "")
    consumer_secret = os.environ.get("PESAPAL_CONSUMER_SECRET", "")
    if not consumer_key or not consumer_secret:
        raise PaymentError("PesaPal credentials not configured.")

    resp = requests.post(
        f"{PESAPAL_BASE_URL}/api/Auth/RequestToken",
        json={"consumer_key": consumer_key, "consumer_secret": consumer_secret},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=15,
    )
    data = resp.json()
    if str(data.get("status")) != "200":
        raise PaymentError(f"PesaPal auth failed: {data.get('message', 'Unknown error')}")

    token = data["token"]
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + 300  # 5-minute validity
    return token


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {_get_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ─────────────────────────────────────────────────────────────────────────────
# IPN Registration (one-time; store ipn_id in env after first run)
# ─────────────────────────────────────────────────────────────────────────────
def register_ipn() -> str:
    """Register our IPN URL with PesaPal and return the ipn_id."""
    ipn_url = os.environ.get(
        "PESAPAL_IPN_URL", "https://mulikascans.com/api/webhooks/pesapal"
    )
    resp = requests.post(
        f"{PESAPAL_BASE_URL}/api/URLSetup/RegisterIPN",
        json={"url": ipn_url, "ipn_notification_type": "POST"},
        headers=_headers(),
        timeout=15,
    )
    data = resp.json()
    if str(data.get("status")) != "200":
        raise PaymentError(f"PesaPal IPN registration failed: {data.get('message')}")
    return data["ipn_id"]


def _get_ipn_id() -> str:
    """Return cached ipn_id from env, or register a new one."""
    ipn_id = os.environ.get("PESAPAL_IPN_ID", "")
    if ipn_id:
        return ipn_id
    return register_ipn()


# ─────────────────────────────────────────────────────────────────────────────
# Create PesaPal checkout
# ─────────────────────────────────────────────────────────────────────────────
def create_subscription_checkout(user, plan_name: str, billing_cycle: str = "monthly"):
    """
    Submit an order to PesaPal.
    Returns (redirect_url, merchant_reference, order_tracking_id).
    """
    key = f"{plan_name}_{billing_cycle}" if plan_name != "enterprise" else "enterprise"
    config = PLAN_CONFIG.get(key)
    if not config:
        raise PaymentError(f"Unknown plan/cycle: {plan_name}/{billing_cycle}")
    if config["amount"] is None:
        raise PaymentError("Enterprise pricing is custom. Contact sales.")

    ipn_id = _get_ipn_id()
    merchant_reference = f"MULIKA-{user.id}-{plan_name}-{billing_cycle}-{int(time.time())}"
    callback_url = os.environ.get(
        "PAYMENT_REDIRECT_URL", "http://localhost:5000/payment/callback"
    )

    name_parts = (user.username or user.email.split("@")[0]).split(" ", 1)
    first_name = name_parts[0]
    last_name = name_parts[1] if len(name_parts) > 1 else ""

    payload = {
        "id": merchant_reference,
        "currency": config["currency"],
        "amount": float(config["amount"]),
        "description": f"MulikaScans {plan_name.title()} Plan — {billing_cycle.title()}",
        "callback_url": callback_url,
        "notification_id": ipn_id,
        "billing_address": {
            "email_address": user.email,
            "first_name": first_name,
            "last_name": last_name,
        },
    }

    resp = requests.post(
        f"{PESAPAL_BASE_URL}/api/Transactions/SubmitOrderRequest",
        json=payload,
        headers=_headers(),
        timeout=15,
    )
    data = resp.json()
    if str(data.get("status")) != "200":
        raise PaymentError(data.get("message", "Failed to create PesaPal checkout"))

    return data["redirect_url"], merchant_reference, data["order_tracking_id"]


# ─────────────────────────────────────────────────────────────────────────────
# Verify / get transaction status
# ─────────────────────────────────────────────────────────────────────────────
def get_transaction_status(order_tracking_id: str) -> dict | None:
    """
    Query PesaPal for transaction status.
    Returns the response dict or None on error.
    CRITICAL: Always verify server-side — never trust client redirect params alone.
    """
    resp = requests.get(
        f"{PESAPAL_BASE_URL}/api/Transactions/GetTransactionStatus",
        params={"orderTrackingId": order_tracking_id},
        headers=_headers(),
        timeout=15,
    )
    data = resp.json()
    if str(data.get("status")) == "200":
        return data
    return None


def is_payment_completed(order_tracking_id: str):
    """
    Returns (True, data) if payment_status_description == 'Completed'.
    Returns (False, data_or_None) otherwise.
    """
    data = get_transaction_status(order_tracking_id)
    if not data:
        return False, None
    completed = data.get("payment_status_description") == "Completed"
    return completed, data


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def parse_payment_method(data: dict) -> str:
    """Return a human-friendly payment method label from PesaPal transaction data."""
    method = (data.get("payment_method") or "").lower()
    if "mpesa" in method or "m-pesa" in method or "m_pesa" in method:
        return "M-Pesa"
    if "airtel" in method:
        return "Airtel Money"
    if "tigo" in method:
        return "Tigo Pesa"
    if "visa" in method or "mastercard" in method or "card" in method:
        return "Card"
    if "bank" in method:
        return "Bank Transfer"
    return data.get("payment_method", "Unknown").title() or "Unknown"


def extract_plan_from_reference(merchant_reference: str):
    """
    Parse user_id, plan, billing_cycle from our merchant reference.
    Format: MULIKA-{user_id}-{plan}-{billing_cycle}-{timestamp}
    """
    try:
        parts = merchant_reference.split("-")
        # e.g. MULIKA-1-basic-monthly-1711111111
        user_id = int(parts[1])
        plan = parts[2]
        billing_cycle = parts[3]
        return user_id, plan, billing_cycle
    except (IndexError, ValueError):
        return None, None, None


def validate_amount(data: dict, plan: str, billing_cycle: str) -> bool:
    key = f"{plan}_{billing_cycle}"
    config = PLAN_CONFIG.get(key)
    if not config or config["amount"] is None:
        return False
    paid = float(data.get("amount", 0))
    currency = (data.get("currency") or "").upper()
    return currency == config["currency"] and paid >= config["amount"]
