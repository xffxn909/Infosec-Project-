"""Admin routes: user management and dashboard statistics."""

from argon2 import PasswordHasher
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity

from app import db
from app.admin import admin_bp
from app.auth.decorators import role_required
from app.models import AuditLog, Document, RoleEnum, Signature, User
from app.utils import generate_user_keys, log_action

ph = PasswordHasher()


@admin_bp.route("/users", methods=["GET"])
@role_required("admin")
def list_users():
    """Return a list of all registered user accounts.

    Returns:
        200 with a JSON array of user dictionaries.
    """
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users]}), 200


@admin_bp.route("/users", methods=["POST"])
@role_required("admin")
def create_user():
    """Create a new user account (admin only).

    Request JSON::

        {
            "email": "bob@example.com",
            "full_name": "Bob Jones",
            "password": "s3cr3t!",
            "role": "manager"
        }

    Returns:
        201 with the new user's data, or an error response.
    """
    caller_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    full_name = data.get("full_name", "").strip()
    password = data.get("password", "")
    role_str = data.get("role", "staff")

    if not email or not full_name or not password:
        return jsonify({"error": "email, full_name, and password are required."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered."}), 409

    try:
        role = RoleEnum[role_str]
    except KeyError:
        return jsonify({"error": f"Invalid role '{role_str}'. Choose from: admin, manager, staff."}), 400

    password_hash = ph.hash(password)
    new_user = User(
        email=email,
        full_name=full_name,
        password_hash=password_hash,
        role=role,
    )
    db.session.add(new_user)
    db.session.flush()

    try:
        private_path, public_path = generate_user_keys(new_user.id)
        new_user.signing_key_path = private_path
        new_user.signing_cert_path = public_path
    except Exception as e:
        pass  # Key generation failure is non-fatal at account creation time

    db.session.commit()

    log_action(
        user_id=caller_id,
        action="admin_create_user",
        resource_type="user",
        resource_id=new_user.id,
        ip=request.remote_addr,
        details={"email": email, "role": role.value},
    )

    return jsonify({"message": "User created.", "user": new_user.to_dict()}), 201


@admin_bp.route("/users/<int:user_id>", methods=["PUT"])
@role_required("admin")
def update_user(user_id: int):
    """Update a user's role or active status (admin only).

    Request JSON (all fields optional)::

        {
            "role": "manager",
            "is_active": true
        }

    Args:
        user_id: Primary key of the user to update.

    Returns:
        200 with the updated user data, or 404 if not found.
    """
    caller_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user is None:
        return jsonify({"error": "User not found."}), 404

    data = request.get_json(silent=True) or {}
    changes = {}

    if "role" in data:
        try:
            new_role = RoleEnum[data["role"]]
            user.role = new_role
            changes["role"] = new_role.value
        except KeyError:
            return jsonify({"error": f"Invalid role '{data['role']}'."}), 400

    if "is_active" in data:
        user.is_active = bool(data["is_active"])
        changes["is_active"] = user.is_active

    if "full_name" in data and data["full_name"].strip():
        user.full_name = data["full_name"].strip()
        changes["full_name"] = user.full_name

    db.session.commit()

    log_action(
        user_id=caller_id,
        action="admin_update_user",
        resource_type="user",
        resource_id=user_id,
        ip=request.remote_addr,
        details=changes,
    )

    return jsonify({"message": "User updated.", "user": user.to_dict()}), 200


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@role_required("admin")
def deactivate_user(user_id: int):
    """Deactivate (soft-delete) a user account (admin only).

    Sets ``is_active=False`` rather than removing the record so that
    historical audit log references remain valid.

    Args:
        user_id: Primary key of the user to deactivate.

    Returns:
        200 on success, 400 if the admin tries to deactivate themselves.
    """
    caller_id = get_jwt_identity()

    if user_id == caller_id:
        return jsonify({"error": "You cannot deactivate your own account."}), 400

    user = User.query.get(user_id)
    if user is None:
        return jsonify({"error": "User not found."}), 404

    user.is_active = False
    db.session.commit()

    log_action(
        user_id=caller_id,
        action="admin_deactivate_user",
        resource_type="user",
        resource_id=user_id,
        ip=request.remote_addr,
        details={"email": user.email},
    )

    return jsonify({"message": f"User '{user.email}' has been deactivated."}), 200


@admin_bp.route("/stats", methods=["GET"])
@role_required("admin", "manager")
def dashboard_stats():
    """Return high-level dashboard statistics.

    Provides counts of total users, active users, documents, signatures,
    and the 10 most recent audit log entries.

    Returns:
        200 with a statistics dictionary.
    """
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_documents = Document.query.filter_by(is_deleted=False).count()
    draft_documents = Document.query.filter_by(is_deleted=False, status="draft").count()
    signed_documents = Document.query.filter_by(is_deleted=False, status="signed").count()
    verified_documents = Document.query.filter_by(is_deleted=False, status="verified").count()
    total_signatures = Signature.query.count()
    valid_signatures = Signature.query.filter_by(is_valid=True).count()

    recent_activity = (
        AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    )

    return jsonify({
        "users": {
            "total": total_users,
            "active": active_users,
            "inactive": total_users - active_users,
        },
        "documents": {
            "total": total_documents,
            "draft": draft_documents,
            "signed": signed_documents,
            "verified": verified_documents,
        },
        "signatures": {
            "total": total_signatures,
            "valid": valid_signatures,
            "invalid": total_signatures - valid_signatures,
        },
        "recent_activity": [entry.to_dict() for entry in recent_activity],
    }), 200
