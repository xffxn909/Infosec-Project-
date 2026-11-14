"""Utility helpers shared across the backend application."""

import os
from typing import Any, Optional

from app.documents.crypto import generate_key_pair


ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "png", "jpg", "jpeg"}


def allowed_file(filename: str) -> bool:
    """Check whether a filename has an allowed extension.

    Args:
        filename: The original filename provided by the client.

    Returns:
        True if the file extension is in the allowed set, False otherwise.
    """
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def log_action(
    user_id: Optional[int],
    action: str,
    resource_type: Optional[str],
    resource_id: Optional[str],
    ip: Optional[str],
    details: Optional[Any] = None,
) -> None:
    """Write an immutable audit log entry to the database.

    Args:
        user_id: ID of the acting user; None for system/anonymous events.
        action: Short verb describing what happened (e.g. "upload", "login").
        resource_type: Category of the affected resource (e.g. "document").
        resource_id: String identifier of the affected resource.
        ip: Remote IP address of the request originator.
        details: Optional dict with additional context; stored as JSON.
    """
    from app import db
    from app.models import AuditLog

    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        ip_address=ip,
        details=details,
    )
    db.session.add(entry)
    db.session.commit()


def generate_user_keys(user_id: int) -> tuple[str, str]:
    """Generate an RSA-2048 key pair for a user and persist them to disk.

    The private key is saved to backend/keys/<user_id>_private.pem and the
    public key to backend/keys/<user_id>_public.pem.  File permissions are set
    to 0o600 on the private key so only the process owner can read it.

    Args:
        user_id: The numeric primary key of the user.

    Returns:
        A tuple (private_key_path, public_key_path) of absolute filesystem
        paths to the saved key files.
    """
    from flask import current_app

    keys_dir = current_app.config["KEYS_FOLDER"]
    os.makedirs(keys_dir, exist_ok=True)

    private_pem, public_pem = generate_key_pair()

    private_path = os.path.join(keys_dir, f"{user_id}_private.pem")
    public_path = os.path.join(keys_dir, f"{user_id}_public.pem")

    with open(private_path, "wb") as f:
        f.write(private_pem)
    os.chmod(private_path, 0o600)

    with open(public_path, "wb") as f:
        f.write(public_pem)

    return private_path, public_path
