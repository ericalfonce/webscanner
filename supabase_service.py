"""
MulikaScans — Supabase Integration
Auth, Storage (bucket: mulikaScan), and PostgreSQL backend.
"""
import os
import threading
from supabase import create_client, Client

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://nfyspkcmkaigqmnqdwte.supabase.co")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "sb_publishable_3aMlmcF8ozYrRaAGvmWcBA_QVTMc8bC")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
STORAGE_BUCKET = os.environ.get("SUPABASE_STORAGE_BUCKET", "mulikaScan")

_client: Client | None = None
_admin_client: Client | None = None
_client_lock = threading.Lock()
_admin_lock = threading.Lock()


def get_supabase() -> Client:
    """Return the shared anon Supabase client (thread-safe lazy init)."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                if not SUPABASE_URL or not SUPABASE_ANON_KEY:
                    raise RuntimeError("SUPABASE_URL and SUPABASE_ANON_KEY must be set.")
                _client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    return _client


def get_supabase_admin() -> Client:
    """Return the shared service-role Supabase client (thread-safe lazy init).

    Use for server-side admin operations: user management, bypassing RLS,
    sending magic links, etc. Never expose this client to the browser.
    """
    global _admin_client
    if _admin_client is None:
        with _admin_lock:
            if _admin_client is None:
                key = SUPABASE_SERVICE_KEY or SUPABASE_ANON_KEY
                if not SUPABASE_URL or not key:
                    raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set.")
                _admin_client = create_client(SUPABASE_URL, key)
    return _admin_client


def create_user_client() -> Client:
    """Create a fresh per-operation anon Supabase client.

    Use this for operations that mutate session state (e.g. sign_in +
    update_user in the same call chain) to avoid racing with the shared
    client used by other concurrent requests.
    """
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise RuntimeError("SUPABASE_URL and SUPABASE_ANON_KEY must be set.")
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


# ── Storage helpers ───────────────────────────────────────────────────────────

def storage_upload(path: str, data: bytes, content_type: str = "application/octet-stream") -> str:
    """Upload bytes to the mulikaScan bucket. Returns the storage path."""
    sb = get_supabase()
    sb.storage.from_(STORAGE_BUCKET).upload(
        path, data, {"content-type": content_type, "upsert": "true"}
    )
    return path


def storage_public_url(path: str) -> str:
    """Return the public URL for a file in the mulikaScan bucket."""
    sb = get_supabase()
    return sb.storage.from_(STORAGE_BUCKET).get_public_url(path)


def storage_download(path: str) -> bytes:
    """Download a file from the mulikaScan bucket."""
    sb = get_supabase()
    return sb.storage.from_(STORAGE_BUCKET).download(path)


def storage_delete(path: str) -> None:
    """Delete a file from the mulikaScan bucket."""
    sb = get_supabase()
    sb.storage.from_(STORAGE_BUCKET).remove([path])
