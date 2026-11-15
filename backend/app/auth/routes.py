"""Auth routes: registration, login, MFA setup/verify, /me, logout."""

import base64
import io

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from app import db, jwt_blocklist
from app.auth import auth_bp
from app.auth.decorators import jwt_required_with_mfa, role_required
from app.models import RoleEnum, User
from app.utils import generate_user_keys, log_action

ph = PasswordHasher()


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account.

    Only an authenticated admin may create new accounts.  The very first user
    in the database is bootstrapped as admin so the system can be initialised
    without a chicken-and-egg problem.

    Request JSON::

        {
            "email": "alice@example.com",
            "full_name": "Alice Smith",
            "password": "s3cr3t!",
            "role": "staff"          # optional, default "staff"
        }

    Returns:
        201 with the new user's public data, or an error response.
    """
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    full_name = data.get("full_name", "").strip()
    password = data.get("password", "")
    role_str = data.get("role", "staff")

    if not email or not full_name or not password:
        return jsonify({"error": "email, full_name, and password are required."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered."}), 409

    # Validate role
    try:
        role = RoleEnum[role_str]
    except KeyError:
        return jsonify({"error": f"Invalid role '{role_str}'. Choose from: admin, manager, staff."}), 400

    # First-ever user becomes admin regardless of requested role
    is_first_user = User.query.count() == 0
    if is_first_user:
        role = RoleEnum.admin
    else:
        # Require admin JWT for all subsequent registrations
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
            verify_jwt_in_request()
            caller_id = get_jwt_identity()
            caller = User.query.get(caller_id)
            if caller is None or caller.role != RoleEnum.admin:
                return jsonify({"error": "Only admins can register new users."}), 403
        except Exception:
            return jsonify({"error": "Authentication required to register users."}), 401

    password_hash = ph.hash(password)

    new_user = User(
        email=email,
        full_name=full_name,
        password_hash=password_hash,
        role=role,
    )
    db.session.add(new_user)
    db.session.flush()  # get the new user ID before commit

    # Auto-generate RSA signing keys for the user
    try:
        private_path, public_path = generate_user_keys(new_user.id)
        new_user.signing_key_path = private_path
        new_user.signing_cert_path = public_path
    except Exception as e:
        current_app.logger.warning(f"Key generation failed for user {new_user.id}: {e}")

    db.session.commit()

    log_action(
        user_id=new_user.id,
        action="register",
        resource_type="user",
        resource_id=new_user.id,
        ip=request.remote_addr,
        details={"email": email, "role": role.value},
    )

    return jsonify({"message": "User created successfully.", "user": new_user.to_dict()}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate a user and return a JWT access token.

    If MFA is enabled on the account the caller must supply the current TOTP
    code in the ``totp_code`` field; without it the request is rejected.

    Request JSON::

        {
            "email": "alice@example.com",
            "password": "s3cr3t!",
            "totp_code": "123456"   # required only when MFA is enabled
        }

    Returns:
        200 with ``{"access_token": "..."}`` on success, or an error response.
    """
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    totp_code = data.get("totp_code", "")

    if not email or not password:
        return jsonify({"error": "email and password are required."}), 400

    user = User.query.filter_by(email=email, is_active=True).first()

    if user is None:
        return jsonify({"error": "Invalid credentials."}), 401

    # Verify password
    try:
        ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        log_action(None, "login_failed", "user", user.id, request.remote_addr,
                   {"reason": "bad_password", "email": email})
        return jsonify({"error": "Invalid credentials."}), 401

    # Rehash if Argon2 parameters have changed
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(password)
        db.session.commit()

    # Enforce MFA if enabled
    if user.mfa_enabled:
        if not totp_code:
            return jsonify({"error": "MFA code required.", "mfa_required": True}), 401
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(totp_code, valid_window=1):
            log_action(user.id, "login_failed", "user", user.id, request.remote_addr,
                       {"reason": "bad_totp"})
            return jsonify({"error": "Invalid MFA code."}), 401

    access_token = create_access_token(identity=user.id)

    log_action(user.id, "login", "user", user.id, request.remote_addr, None)

    return jsonify({
        "access_token": access_token,
        "user": user.to_dict(),
    }), 200


@auth_bp.route("/mfa/setup", methods=["POST"])
@jwt_required()
def mfa_setup():
    """Generate a new TOTP secret and return a QR-code PNG as base64.

    The secret is persisted to the user record but MFA is NOT yet enabled;
    the client must call ``POST /mfa/verify`` with a valid code first.

    Returns:
        200 with ``{"secret": "...", "qr_code": "<base64 PNG>", "otpauth_url": "..."}``.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user is None:
        return jsonify({"error": "User not found."}), 404

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(
        name=user.email,
        issuer_name=current_app.config["MFA_ISSUER"],
    )

    # Generate QR code image
    img = qrcode.make(otpauth_url)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    # Persist the secret (MFA stays disabled until verified)
    user.mfa_secret = secret
    db.session.commit()

    log_action(user_id, "mfa_setup_initiated", "user", user_id, request.remote_addr, None)

    return jsonify({
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_code": qr_b64,
    }), 200


@auth_bp.route("/mfa/verify", methods=["POST"])
@jwt_required()
def mfa_verify():
    """Verify a TOTP code and activate MFA on the account.

    Request JSON::

        {"totp_code": "123456"}

    Returns:
        200 on success, 400 if the code is invalid.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user is None:
        return jsonify({"error": "User not found."}), 404

    if not user.mfa_secret:
        return jsonify({"error": "MFA setup not initiated. Call /mfa/setup first."}), 400

    data = request.get_json(silent=True) or {}
    totp_code = data.get("totp_code", "")

    if not totp_code:
        return jsonify({"error": "totp_code is required."}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({"error": "Invalid TOTP code."}), 400

    user.mfa_enabled = True
    db.session.commit()

    log_action(user_id, "mfa_enabled", "user", user_id, request.remote_addr, None)

    return jsonify({"message": "MFA enabled successfully."}), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """Return the currently authenticated user's public profile.

    Returns:
        200 with the user's public data dictionary.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user is None or not user.is_active:
        return jsonify({"error": "User not found or inactive."}), 404

    return jsonify({"user": user.to_dict()}), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """Invalidate the current JWT by adding its JTI to the in-memory blocklist.

    Returns:
        200 with a confirmation message.
    """
    jti = get_jwt()["jti"]
    jwt_blocklist.add(jti)

    user_id = get_jwt_identity()
    log_action(user_id, "logout", "user", user_id, request.remote_addr, None)

    return jsonify({"message": "Successfully logged out."}), 200
