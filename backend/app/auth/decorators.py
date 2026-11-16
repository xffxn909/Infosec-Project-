"""Custom decorators for JWT + RBAC enforcement."""

from functools import wraps
from typing import Callable, List

from flask import jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from app.models import RoleEnum


def jwt_required_with_mfa(fn: Callable) -> Callable:
    """Decorator that enforces a valid JWT access token.

    Acts as a thin wrapper around flask_jwt_extended's verify_jwt_in_request
    so we have one place to add extra checks (e.g. device fingerprint) in the
    future without touching every route.

    Args:
        fn: The view function to protect.

    Returns:
        The wrapped function that aborts with 401 when the token is absent or
        invalid.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except Exception as exc:
            return jsonify({"error": str(exc)}), 401
        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles: str) -> Callable:
    """Factory that returns a decorator enforcing one of the given RBAC roles.

    Usage::

        @role_required("admin", "manager")
        def my_view():
            ...

    Args:
        *roles: One or more role names (strings) that are permitted to call
                the decorated view.

    Returns:
        A decorator that rejects requests whose JWT identity does not carry
        an allowed role with HTTP 403.
    """

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
            except Exception as exc:
                return jsonify({"error": str(exc)}), 401

            from app.models import User

            user_id = get_jwt_identity()
            user = User.query.get(user_id)

            if user is None or not user.is_active:
                return jsonify({"error": "User not found or inactive."}), 403

            if user.role.value not in roles:
                return (
                    jsonify(
                        {
                            "error": f"Access denied. Required role(s): {', '.join(roles)}."
                        }
                    ),
                    403,
                )

            return fn(*args, **kwargs)

        return wrapper

    return decorator
