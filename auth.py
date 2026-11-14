"""
auth.py
=======
Module 1 – Authentication & Authorization
  - Multi-factor authentication (TOTP via pyotp)
  - Role-based access control (admin, manager, staff)
  - Session token management
  - Rate limiting (in-memory, against DoS / brute-force)
"""

import os
import time
import base64
import secrets
import datetime
from collections import defaultdict
from functools import wraps

try:
    import pyotp
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False
    print("[Auth] WARNING: pyotp not installed – MFA disabled. Run: pip install pyotp")

from database import (
    get_user, create_session, get_session, delete_session, audit
)
from pki_manager import verify_password, hash_password

# ─────────────────────────────────────────────────────────────────────────────
# Rate Limiter  (in-memory; in production use Redis)
# ─────────────────────────────────────────────────────────────────────────────

_attempts: dict[str, list[float]] = defaultdict(list)
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 300   # 5 minutes


def _record_attempt(ip: str):
    now = time.time()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < _WINDOW_SECONDS]
    _attempts[ip].append(now)


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _attempts[ip] if now - t < _WINDOW_SECONDS]
    return len(recent) >= _MAX_ATTEMPTS


# ─────────────────────────────────────────────────────────────────────────────
# MFA – TOTP
# ─────────────────────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """Generate a base32 TOTP secret for a new user."""
    if not TOTP_AVAILABLE:
        return ""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Return an otpauth:// URI (scan with Authenticator app)."""
    if not TOTP_AVAILABLE:
        return ""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureDocSystem")


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code (±30 s window)."""
    if not TOTP_AVAILABLE:
        return True          # MFA skipped if pyotp absent
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def get_current_totp(secret: str) -> str:
    """Generate the current live 6-digit TOTP code (for testing / demo)."""
    if not TOTP_AVAILABLE or not secret:
        return ""
    return pyotp.TOTP(secret).now()


# ─────────────────────────────────────────────────────────────────────────────
# Login / Logout
# ─────────────────────────────────────────────────────────────────────────────

class AuthError(Exception):
    pass


def login(username: str, password: str, totp_code: str = None,
          ip: str = "127.0.0.1") -> str:
    """
    Authenticate a user. Returns a session token.
    Raises AuthError on failure.
    """
    if _is_rate_limited(ip):
        raise AuthError("Too many login attempts. Try again in 5 minutes.")

    user = get_user(username)
    if not user:
        _record_attempt(ip)
        audit("SYSTEM", "LOGIN_FAIL", username, "User not found", ip)
        raise AuthError("Invalid credentials.")

    if not verify_password(user["password"], password):
        _record_attempt(ip)
        audit("SYSTEM", "LOGIN_FAIL", username, "Bad password", ip)
        raise AuthError("Invalid credentials.")

    # MFA check
    if user.get("totp_secret") and TOTP_AVAILABLE:
        if not totp_code:
            raise AuthError("MFA code required.")
        if not verify_totp(user["totp_secret"], totp_code):
            _record_attempt(ip)
            audit("SYSTEM", "LOGIN_FAIL", username, "Bad TOTP", ip)
            raise AuthError("Invalid MFA code.")

    token = secrets.token_urlsafe(32)
    create_session(token, username)
    audit(username, "LOGIN_OK", ip=ip)
    return token


def logout(token: str):
    session = get_session(token)
    if session:
        audit(session["username"], "LOGOUT")
        delete_session(token)


def get_current_user(token: str) -> dict | None:
    """Return the user dict for a valid session, else None."""
    session = get_session(token)
    if not session:
        return None
    return get_user(session["username"])


# ─────────────────────────────────────────────────────────────────────────────
# Role-Based Access Control
# ─────────────────────────────────────────────────────────────────────────────

ROLE_HIERARCHY = {"admin": 3, "manager": 2, "staff": 1}


def has_permission(user: dict, min_role: str) -> bool:
    user_level = ROLE_HIERARCHY.get(user.get("role", "staff"), 0)
    required_level = ROLE_HIERARCHY.get(min_role, 99)
    return user_level >= required_level


def require_role(min_role: str):
    """Decorator for functions that accept user dict as first arg."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(user, *args, **kwargs):
            if not has_permission(user, min_role):
                raise AuthError(f"Role '{min_role}' or higher required.")
            return fn(user, *args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from database import init_db, create_user

    init_db()

    secret = generate_totp_secret()
    pw_hash = hash_password("Test@1234")
    try:
        create_user("bob", pw_hash, role="manager", totp_secret=secret)
        print("[Auth] Created user 'bob' (manager)")
    except Exception as e:
        print(f"[Auth] User may already exist: {e}")

    print(f"[Auth] TOTP URI: {get_totp_uri(secret, 'bob')}")

    # Login without MFA code (skips if pyotp absent)
    try:
        token = login("bob", "Test@1234", ip="192.168.1.1")
        print(f"[Auth] Login OK, token: {token[:20]}…")

        user = get_current_user(token)
        print(f"[Auth] Session user: {user['username']} / {user['role']}")

        @require_role("admin")
        def admin_only_action(user):
            print("[Auth] Admin action executed!")

        try:
            admin_only_action(user)
        except AuthError as e:
            print(f"[Auth] RBAC blocked (expected): {e}")

        logout(token)
        print("[Auth] Logged out. Session invalidated.")
    except AuthError as e:
        print(f"[Auth] Login error: {e}")
