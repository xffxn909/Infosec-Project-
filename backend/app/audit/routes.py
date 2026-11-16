"""Audit log routes: paginated listing and CSV export."""

import csv
import io
from datetime import datetime

from flask import jsonify, make_response, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from app.audit import audit_bp
from app.auth.decorators import role_required
from app.models import AuditLog


@audit_bp.route("/", methods=["GET"])
@role_required("admin", "manager")
def list_audit_logs():
    """Return a paginated, filtered list of audit log entries.

    Query parameters
    ----------------
    page : int, default 1
        Page number (1-based).
    per_page : int, default 50, max 200
        Number of entries per page.
    user_id : int, optional
        Filter by acting user ID.
    action : str, optional
        Filter by action verb (case-insensitive substring match).
    start_date : str, optional
        ISO-8601 date lower bound (inclusive), e.g. ``2024-01-01``.
    end_date : str, optional
        ISO-8601 date upper bound (inclusive), e.g. ``2024-12-31``.

    Returns:
        200 with ``{logs: [...], total, page, per_page, pages}``.
    """
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    user_id_filter = request.args.get("user_id", type=int)
    action_filter = request.args.get("action", "")
    start_date_str = request.args.get("start_date", "")
    end_date_str = request.args.get("end_date", "")

    query = AuditLog.query

    if user_id_filter:
        query = query.filter(AuditLog.user_id == user_id_filter)

    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))

    if start_date_str:
        try:
            start_dt = datetime.fromisoformat(start_date_str)
            query = query.filter(AuditLog.timestamp >= start_dt)
        except ValueError:
            return jsonify({"error": "Invalid start_date format. Use ISO-8601."}), 400

    if end_date_str:
        try:
            end_dt = datetime.fromisoformat(end_date_str)
            query = query.filter(AuditLog.timestamp <= end_dt)
        except ValueError:
            return jsonify({"error": "Invalid end_date format. Use ISO-8601."}), 400

    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        "logs": [entry.to_dict() for entry in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": per_page,
        "pages": pagination.pages,
    }), 200


@audit_bp.route("/export", methods=["GET"])
@role_required("admin")
def export_audit_logs():
    """Export the full audit log as a CSV file (admin only).

    Accepts the same query-string filters as ``GET /``.

    Returns:
        A ``text/csv`` attachment named ``audit_log_<timestamp>.csv``.
    """
    user_id_filter = request.args.get("user_id", type=int)
    action_filter = request.args.get("action", "")
    start_date_str = request.args.get("start_date", "")
    end_date_str = request.args.get("end_date", "")

    query = AuditLog.query

    if user_id_filter:
        query = query.filter(AuditLog.user_id == user_id_filter)

    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))

    if start_date_str:
        try:
            start_dt = datetime.fromisoformat(start_date_str)
            query = query.filter(AuditLog.timestamp >= start_dt)
        except ValueError:
            return jsonify({"error": "Invalid start_date format."}), 400

    if end_date_str:
        try:
            end_dt = datetime.fromisoformat(end_date_str)
            query = query.filter(AuditLog.timestamp <= end_dt)
        except ValueError:
            return jsonify({"error": "Invalid end_date format."}), 400

    logs = query.order_by(AuditLog.timestamp.asc()).all()

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "timestamp", "user_id", "action", "resource_type",
                    "resource_id", "ip_address", "details"],
        extrasaction="ignore",
    )
    writer.writeheader()
    for entry in logs:
        row = entry.to_dict()
        row["details"] = str(row.get("details", ""))
        writer.writerow(row)

    csv_content = output.getvalue()
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"audit_log_{timestamp_str}.csv"

    response = make_response(csv_content)
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response
