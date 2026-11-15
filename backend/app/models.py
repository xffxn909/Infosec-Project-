"""SQLAlchemy ORM models for the Secure Document Management System."""

import enum
from datetime import datetime

from app import db


class RoleEnum(enum.Enum):
    """Allowed user roles for RBAC."""

    admin = "admin"
    manager = "manager"
    staff = "staff"


class StatusEnum(enum.Enum):
    """Document lifecycle statuses."""

    draft = "draft"
    signed = "signed"
    verified = "verified"


class User(db.Model):
    """Represents an authenticated system user.

    Attributes:
        id: Primary key.
        email: Unique e-mail used as the login identifier.
        full_name: Display name of the user.
        password_hash: Argon2id hash of the user's password.
        role: RBAC role (admin | manager | staff).
        mfa_secret: Base-32 TOTP secret; None until MFA is set up.
        mfa_enabled: Whether TOTP MFA is active on this account.
        signing_cert_path: Filesystem path to the user's public-key certificate.
        signing_key_path: Filesystem path to the user's RSA private key (PEM).
        is_active: Soft-delete / account suspension flag.
        created_at: Account creation timestamp (UTC).
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.Enum(RoleEnum), nullable=False, default=RoleEnum.staff)
    mfa_secret = db.Column(db.String(64), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    signing_cert_path = db.Column(db.String(512), nullable=True)
    signing_key_path = db.Column(db.String(512), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    documents = db.relationship("Document", backref="uploader", lazy=True)
    signatures = db.relationship("Signature", backref="signer", lazy=True)
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True)

    def to_dict(self) -> dict:
        """Serialise the user to a JSON-safe dictionary (no secrets)."""
        return {
            "id": self.id,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role.value,
            "mfa_enabled": self.mfa_enabled,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }


class Document(db.Model):
    """Represents an uploaded document.

    Attributes:
        id: Primary key.
        title: Human-readable title for the document.
        description: Optional longer description.
        filename: Hashed filename used on disk (prevents enumeration).
        original_filename: Original name provided at upload time.
        file_hash: SHA-256 hex digest of the file content at upload time.
        uploader_id: FK to the User who uploaded the document.
        status: Lifecycle status (draft | signed | verified).
        is_deleted: Soft-delete flag.
        created_at: Upload timestamp (UTC).
        updated_at: Last modification timestamp (UTC).
    """

    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(255), nullable=False, unique=True)
    original_filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hex
    uploader_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    status = db.Column(db.Enum(StatusEnum), nullable=False, default=StatusEnum.draft)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    # Relationships
    signatures = db.relationship("Signature", backref="document", lazy=True)

    def to_dict(self) -> dict:
        """Serialise the document to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "original_filename": self.original_filename,
            "file_hash": self.file_hash,
            "uploader_id": self.uploader_id,
            "status": self.status.value,
            "is_deleted": self.is_deleted,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class Signature(db.Model):
    """Records a digital signature applied to a document.

    Attributes:
        id: Primary key.
        document_id: FK to the signed Document.
        signer_id: FK to the User who applied the signature.
        signature_data: Base-64 encoded RSA signature bytes.
        signed_at: Timestamp when the signature was applied (UTC).
        is_valid: Cached result of the most recent verification run.
    """

    __tablename__ = "signatures"

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("documents.id"), nullable=False, index=True
    )
    signer_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    signature_data = db.Column(db.Text, nullable=False)  # base64
    signed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_valid = db.Column(db.Boolean, default=True, nullable=False)

    def to_dict(self) -> dict:
        """Serialise the signature record to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "document_id": self.document_id,
            "signer_id": self.signer_id,
            "signature_data": self.signature_data,
            "signed_at": self.signed_at.isoformat(),
            "is_valid": self.is_valid,
        }


class AuditLog(db.Model):
    """Immutable audit trail entry.

    Attributes:
        id: Primary key.
        user_id: FK to the acting User; nullable for anonymous/system events.
        action: Short verb describing the action (e.g. "upload", "sign").
        resource_type: Category of the affected resource (e.g. "document").
        resource_id: String identifier of the affected resource.
        ip_address: Remote IP of the request originator.
        details: Arbitrary JSON payload for extra context.
        timestamp: When the event occurred (UTC).
    """

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, index=True
    )
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(100), nullable=True)
    resource_id = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.JSON, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self) -> dict:
        """Serialise the audit log entry to a JSON-safe dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }
