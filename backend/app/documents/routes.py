"""Document management routes: upload, list, download, sign, verify, delete."""

import hashlib
import os
import uuid

from flask import current_app, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required

from app import db
from app.auth.decorators import role_required
from app.documents import documents_bp
from app.documents.crypto import compute_sha256, sign_document, verify_signature
from app.models import Document, RoleEnum, Signature, StatusEnum, User
from app.utils import allowed_file, log_action


def _hashed_filename(original_filename: str) -> str:
    """Derive a collision-resistant storage filename from the original name.

    Uses a UUID4 combined with the original extension so that:
    - stored filenames cannot be guessed from original names, and
    - the extension is preserved for MIME-type detection.

    Args:
        original_filename: The original filename provided by the client.

    Returns:
        A unique filename string safe for filesystem storage.
    """
    ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else "bin"
    return f"{uuid.uuid4().hex}.{ext}"


@documents_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload_document():
    """Upload a new document.

    Accepts ``multipart/form-data`` with the file field named ``file`` plus
    optional ``title`` and ``description`` text fields.  Computes a SHA-256
    hash of the uploaded content, stores the file under a randomised filename,
    and creates a Document record.

    Returns:
        201 with the new document's data, or an appropriate error response.
    """
    user_id = get_jwt_identity()

    if "file" not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed. Permitted: pdf, docx, txt, png, jpg."}), 400

    title = request.form.get("title", file.filename).strip()
    description = request.form.get("description", "").strip()

    stored_filename = _hashed_filename(file.filename)
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, stored_filename)

    try:
        file.save(filepath)
        file_hash = compute_sha256(filepath)

        doc = Document(
            title=title,
            description=description,
            filename=stored_filename,
            original_filename=file.filename,
            file_hash=file_hash,
            uploader_id=user_id,
            status=StatusEnum.draft,
        )
        db.session.add(doc)
        db.session.commit()

        log_action(
            user_id=user_id,
            action="upload",
            resource_type="document",
            resource_id=doc.id,
            ip=request.remote_addr,
            details={"original_filename": file.filename, "sha256": file_hash},
        )

        return jsonify({"message": "Document uploaded successfully.", "document": doc.to_dict()}), 201

    except Exception as exc:
        # Clean up partially written file on error
        if os.path.exists(filepath):
            os.remove(filepath)
        current_app.logger.error(f"Upload failed: {exc}")
        return jsonify({"error": "Upload failed. Please try again."}), 500


@documents_bp.route("/", methods=["GET"])
@jwt_required()
def list_documents():
    """List documents accessible to the current user.

    - Staff members see only their own (non-deleted) documents.
    - Managers and admins see all non-deleted documents.

    Returns:
        200 with a JSON array of document dictionaries.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user is None or not user.is_active:
        return jsonify({"error": "User not found."}), 404

    query = Document.query.filter_by(is_deleted=False)
    if user.role == RoleEnum.staff:
        query = query.filter_by(uploader_id=user_id)

    documents = query.order_by(Document.created_at.desc()).all()
    return jsonify({"documents": [d.to_dict() for d in documents]}), 200


@documents_bp.route("/<int:doc_id>", methods=["GET"])
@jwt_required()
def get_document(doc_id: int):
    """Retrieve details of a single document including its stored SHA-256 hash.

    Args:
        doc_id: Primary key of the document.

    Returns:
        200 with document data, or 404 / 403 as appropriate.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first()

    if doc is None:
        return jsonify({"error": "Document not found."}), 404

    if user.role == RoleEnum.staff and doc.uploader_id != user_id:
        return jsonify({"error": "Access denied."}), 403

    sigs = [s.to_dict() for s in doc.signatures]
    data = doc.to_dict()
    data["signatures"] = sigs
    return jsonify({"document": data}), 200


@documents_bp.route("/<int:doc_id>/download", methods=["GET"])
@jwt_required()
def download_document(doc_id: int):
    """Download a document file, re-verifying its SHA-256 hash on the way out.

    Re-computing the hash on download detects any file tampering that occurred
    after upload.

    Args:
        doc_id: Primary key of the document.

    Returns:
        The file as an attachment, or an error response if the hash does not
        match (indicating file tampering).
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first()

    if doc is None:
        return jsonify({"error": "Document not found."}), 404

    if user.role == RoleEnum.staff and doc.uploader_id != user_id:
        return jsonify({"error": "Access denied."}), 403

    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], doc.filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found on server."}), 404

    # Integrity check
    current_hash = compute_sha256(filepath)
    if current_hash != doc.file_hash:
        log_action(
            user_id=user_id,
            action="integrity_failure",
            resource_type="document",
            resource_id=doc_id,
            ip=request.remote_addr,
            details={"expected": doc.file_hash, "actual": current_hash},
        )
        return jsonify({"error": "File integrity check failed. The file may have been tampered with."}), 500

    log_action(user_id, "download", "document", doc_id, request.remote_addr, None)

    return send_file(
        filepath,
        as_attachment=True,
        download_name=doc.original_filename,
    )


@documents_bp.route("/<int:doc_id>/sign", methods=["POST"])
@jwt_required()
def sign_document_route(doc_id: int):
    """Sign a document with the current user's RSA private key.

    Reads the user's private key from ``backend/keys/<user_id>_private.pem``,
    computes the RSA-PSS signature over the document's SHA-256 hash, persists
    the Signature record, and updates the document status to ``signed``.

    Args:
        doc_id: Primary key of the document to sign.

    Returns:
        200 with the new signature record, or an error response.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first()

    if doc is None:
        return jsonify({"error": "Document not found."}), 404

    if user.role == RoleEnum.staff and doc.uploader_id != user_id:
        return jsonify({"error": "Access denied. You can only sign your own documents."}), 403

    if not user.signing_key_path or not os.path.exists(user.signing_key_path):
        return jsonify({"error": "Signing key not found. Please contact an administrator."}), 400

    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], doc.filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Document file not found on server."}), 404

    try:
        with open(user.signing_key_path, "rb") as kf:
            private_key_pem = kf.read()

        signature_b64 = sign_document(filepath, private_key_pem)

        sig = Signature(
            document_id=doc_id,
            signer_id=user_id,
            signature_data=signature_b64,
            is_valid=True,
        )
        db.session.add(sig)

        doc.status = StatusEnum.signed
        db.session.commit()

        log_action(
            user_id=user_id,
            action="sign",
            resource_type="document",
            resource_id=doc_id,
            ip=request.remote_addr,
            details={"signature_id": sig.id},
        )

        return jsonify({"message": "Document signed successfully.", "signature": sig.to_dict()}), 200

    except Exception as exc:
        current_app.logger.error(f"Signing failed for doc {doc_id}: {exc}")
        return jsonify({"error": "Signing failed. Please try again."}), 500


@documents_bp.route("/<int:doc_id>/verify", methods=["POST"])
@jwt_required()
def verify_document(doc_id: int):
    """Verify the integrity and digital signatures of a document.

    Checks:
    1. SHA-256 hash of the stored file matches the recorded hash.
    2. Each signature record is valid against the signer's public key.

    Updates ``is_valid`` on each Signature record and document status to
    ``verified`` when all checks pass.

    Args:
        doc_id: Primary key of the document.

    Returns:
        200 with a detailed verification report.
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first()

    if doc is None:
        return jsonify({"error": "Document not found."}), 404

    if user.role == RoleEnum.staff and doc.uploader_id != user_id:
        return jsonify({"error": "Access denied."}), 403

    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], doc.filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Document file not found on server."}), 404

    result = {
        "document_id": doc_id,
        "hash_valid": False,
        "signatures": [],
        "overall_valid": False,
    }

    # 1. Hash integrity check
    current_hash = compute_sha256(filepath)
    result["hash_valid"] = current_hash == doc.file_hash
    result["expected_hash"] = doc.file_hash
    result["current_hash"] = current_hash

    # 2. Signature verification
    all_sigs_valid = True
    for sig in doc.signatures:
        signer = User.query.get(sig.signer_id)
        sig_result = {
            "signature_id": sig.id,
            "signer_id": sig.signer_id,
            "signer_email": signer.email if signer else "unknown",
            "signed_at": sig.signed_at.isoformat(),
            "valid": False,
        }

        if signer and signer.signing_cert_path and os.path.exists(signer.signing_cert_path):
            try:
                with open(signer.signing_cert_path, "rb") as pf:
                    public_key_pem = pf.read()
                is_valid = verify_signature(filepath, sig.signature_data, public_key_pem)
                sig_result["valid"] = is_valid
                sig.is_valid = is_valid
                if not is_valid:
                    all_sigs_valid = False
            except Exception as exc:
                sig_result["valid"] = False
                sig_result["error"] = str(exc)
                all_sigs_valid = False
        else:
            sig_result["valid"] = False
            sig_result["error"] = "Signer public key not available."
            all_sigs_valid = False

        result["signatures"].append(sig_result)

    result["overall_valid"] = result["hash_valid"] and all_sigs_valid

    if result["overall_valid"]:
        doc.status = StatusEnum.verified

    db.session.commit()

    log_action(
        user_id=user_id,
        action="verify",
        resource_type="document",
        resource_id=doc_id,
        ip=request.remote_addr,
        details={"overall_valid": result["overall_valid"]},
    )

    return jsonify({"verification": result}), 200


@documents_bp.route("/<int:doc_id>", methods=["DELETE"])
@role_required("admin", "manager")
def delete_document(doc_id: int):
    """Soft-delete a document (admin or manager only).

    Sets ``is_deleted=True`` without removing the underlying file so that
    audit trails and signatures remain intact.

    Args:
        doc_id: Primary key of the document to delete.

    Returns:
        200 on success, 404 if not found.
    """
    from flask_jwt_extended import get_jwt_identity
    user_id = get_jwt_identity()

    doc = Document.query.filter_by(id=doc_id, is_deleted=False).first()
    if doc is None:
        return jsonify({"error": "Document not found."}), 404

    doc.is_deleted = True
    db.session.commit()

    log_action(
        user_id=user_id,
        action="delete",
        resource_type="document",
        resource_id=doc_id,
        ip=request.remote_addr,
        details={"title": doc.title},
    )

    return jsonify({"message": "Document deleted successfully."}), 200
