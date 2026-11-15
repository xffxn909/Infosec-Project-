"""Documents blueprint package."""

from flask import Blueprint

documents_bp = Blueprint("documents", __name__)

from app.documents import routes  # noqa: F401, E402
