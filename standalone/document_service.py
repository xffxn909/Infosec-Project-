"""
document_service.py
====================
Module 1 – Document Upload, Signing & Verification
  - Secure upload with SHA-256 fingerprinting
  - ECDSA digital signing (per-user key from PKI)
  - Tamper detection
  - Audit trail for all operations
"""

import uuid
import shutil
from pathlib import Path

from pki_manager import (
    sha256_file, sign_document, verify_document,
    tamper_check, load_private_key, load_cert,
)
from database import (
    add_document, get_document, list_documents,
    mark_signed, audit, is_cert_revoked,
)

UPLOAD_DIR = Path("uploads")
PKI_DIR = Path("pki")
UPLOAD_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Upload
# ─────────────────────────────────────────────────────────────────────────────

def upload_document(source_path: Path, uploader: str, ip: str = "127.0.0.1") -> dict:
    """
    Copy a file into the secure uploads directory, compute its SHA-256,
    record it in the DB, and log the action.
    Returns the document record dict.
    """
    if not source_path.exists():
        raise FileNotFoundError(f"File not found: {source_path}")

    stored_name = uuid.uuid4().hex + source_path.suffix
    dest = UPLOAD_DIR / stored_name
    shutil.copy2(source_path, dest)

    file_hash = sha256_file(dest)
    add_document(
        filename=source_path.name,
        stored_name=stored_name,
        uploader=uploader,
        sha256=file_hash,
    )
    audit(uploader, "UPLOAD", target=stored_name,
          detail=f"Original: {source_path.name} SHA256: {file_hash}", ip=ip)
    print(f"[DocService] Uploaded '{source_path.name}' → {stored_name} (SHA-256: {file_hash[:16]}…)")
    return get_document(stored_name)


# ─────────────────────────────────────────────────────────────────────────────
# Sign
# ─────────────────────────────────────────────────────────────────────────────

def sign_doc(stored_name: str, signer_username: str, ip: str = "127.0.0.1") -> bool:
    """
    Sign a document using the signer's ECDSA key from PKI.
    Checks certificate is not revoked.
    """
    doc = get_document(stored_name)
    if not doc:
        raise ValueError(f"Document '{stored_name}' not found.")

    # Load user's signing key & cert
    user_dir = PKI_DIR / "users" / signer_username
    key_path = user_dir / "signing.key"
    cert_path = user_dir / "signing.crt"

    if not key_path.exists() or not cert_path.exists():
        raise FileNotFoundError(
            f"No signing credentials for '{signer_username}'. "
            "Issue a certificate first via pki_manager.issue_user_cert()"
        )

    # Revocation check
    cert = load_cert(cert_path)
    serial_hex = hex(cert.serial_number)
    if is_cert_revoked(serial_hex):
        raise PermissionError(f"Certificate for '{signer_username}' has been revoked.")

    signing_key = load_private_key(key_path)
    filepath = UPLOAD_DIR / stored_name

    sig = sign_document(filepath, signing_key)
    mark_signed(stored_name, signer_username, sig_valid=True)
    audit(signer_username, "SIGN", target=stored_name,
          detail=f"Cert serial: {serial_hex}", ip=ip)
    print(f"[DocService] '{stored_name}' signed by '{signer_username}'")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Verify
# ─────────────────────────────────────────────────────────────────────────────

def verify_doc(stored_name: str, verifier: str, ip: str = "127.0.0.1") -> dict:
    """
    Verify a document's integrity:
      1. SHA-256 hash match (tamper check)
      2. ECDSA signature verification
    Returns a result dict with 'hash_ok', 'sig_ok', 'tampered'.
    """
    doc = get_document(stored_name)
    if not doc:
        raise ValueError(f"Document '{stored_name}' not found.")

    filepath = UPLOAD_DIR / stored_name
    sig_path = Path(str(filepath) + ".sig")

    # 1. Hash / tamper check
    hash_ok = tamper_check(filepath, doc["sha256"])

    # 2. Signature check (if signed)
    sig_ok = False
    if doc.get("signed_by") and sig_path.exists():
        signer = doc["signed_by"]
        cert_path = PKI_DIR / "users" / signer / "signing.crt"
        if cert_path.exists():
            cert = load_cert(cert_path)
            sig_bytes = sig_path.read_bytes()

            # Check revocation
            serial_hex = hex(cert.serial_number)
            if not is_cert_revoked(serial_hex):
                sig_ok = verify_document(filepath, sig_bytes, cert.public_key())

    result = {
        "document": stored_name,
        "original_name": doc["filename"],
        "uploader": doc["uploader"],
        "signed_by": doc.get("signed_by"),
        "hash_ok": hash_ok,
        "sig_ok": sig_ok,
        "tampered": not hash_ok,
        "status": "✅ VALID" if (hash_ok and (sig_ok or not doc.get("signed_by"))) else "❌ TAMPERED / INVALID",
    }

    audit(verifier, "VERIFY", target=stored_name,
          detail=f"hash_ok={hash_ok} sig_ok={sig_ok}", ip=ip)
    print(f"[DocService] Verification result for '{stored_name}': {result['status']}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# List
# ─────────────────────────────────────────────────────────────────────────────

def list_docs(requester: str, role: str = "staff") -> list[dict]:
    """Admins and managers see all docs; staff see only their own."""
    if role in ("admin", "manager"):
        docs = list_documents()
    else:
        docs = list_documents(uploader=requester)
    audit(requester, "LIST_DOCS", detail=f"role={role}")
    return docs


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from database import init_db, create_user
    from pki_manager import create_root_ca, create_intermediate_ca, issue_user_cert, hash_password

    init_db()

    # Build PKI
    root_key, root_cert = create_root_ca()
    int_key, int_cert = create_intermediate_ca(root_key, root_cert)
    issue_user_cert("alice", int_key, int_cert)

    # Ensure user exists
    try:
        create_user("alice", hash_password("Test@1234"), role="staff")
    except Exception:
        pass  # already exists

    # Create a dummy document
    test_file = Path("sample_contract.txt")
    test_file.write_text("Contract between Party A and Party B dated today.")

    # Upload → Sign → Verify
    doc = upload_document(test_file, uploader="alice")
    sign_doc(doc["stored_name"], signer_username="alice")
    result = verify_doc(doc["stored_name"], verifier="alice")
    print("\n--- Verification (clean) ---")
    for k, v in result.items():
        print(f"  {k}: {v}")

    # Tamper with the stored file
    (UPLOAD_DIR / doc["stored_name"]).write_text("HACKED CONTENT")
    result2 = verify_doc(doc["stored_name"], verifier="alice")
    print("\n--- Verification (tampered) ---")
    for k, v in result2.items():
        print(f"  {k}: {v}")

    test_file.unlink(missing_ok=True)
