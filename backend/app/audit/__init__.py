"""Audit log blueprint package."""

from flask import Blueprint

audit_bp = Blueprint("audit", __name__)

from app.audit import routes  # noqa: F401, E402
