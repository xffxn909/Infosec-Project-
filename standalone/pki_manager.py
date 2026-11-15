"""
pki_manager.py
==============
Module 1 – Cryptographic Components
Handles:
  - Root CA and Intermediate CA creation (OpenSSL-compatible via cryptography lib)
  - Certificate issuance and revocation (CRL)
  - RSA / ECDSA digital signing of documents
  - SHA-256 document hashing & tamper detection
  - Password hashing with Argon2 (bcrypt fallback)
  - Key management (rotation schedule, offline root key concept)
"""

import os
import json
import hashlib
import datetime
import ipaddress
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.x509 import CertificateRevocationList
import argon2
from argon2 import PasswordHasher

PKI_DIR = Path("pki")
PKI_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Key Generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_rsa_key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def save_private_key(key, path: Path, password: Optional[bytes] = None):
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    )


def load_private_key(path: Path, password: Optional[bytes] = None):
    return serialization.load_pem_private_key(path.read_bytes(), password=password)


def save_cert(cert, path: Path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path: Path):
    return x509.load_pem_x509_certificate(path.read_bytes())


# ─────────────────────────────────────────────────────────────────────────────
# Certificate Authority
# ─────────────────────────────────────────────────────────────────────────────

def _build_name(cn: str, org: str = "SecureDocLab", country: str = "PK"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def create_root_ca(bits: int = 4096, validity_years: int = 10) -> tuple:
    """Generate Root CA key + self-signed certificate."""
    key = generate_rsa_key(bits)
    name = _build_name("SecureDoc Root CA")
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * validity_years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    root_key_path = PKI_DIR / "root_ca.key"
    root_cert_path = PKI_DIR / "root_ca.crt"
    save_private_key(key, root_key_path)   # In real use: keep this OFFLINE
    save_cert(cert, root_cert_path)
    print(f"[PKI] Root CA created → {root_cert_path}")
    return key, cert


def create_intermediate_ca(root_key, root_cert, bits: int = 2048, validity_years: int = 5) -> tuple:
    """Generate Intermediate CA signed by Root CA."""
    key = generate_rsa_key(bits)
    name = _build_name("SecureDoc Intermediate CA")
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * validity_years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    int_key_path = PKI_DIR / "intermediate_ca.key"
    int_cert_path = PKI_DIR / "intermediate_ca.crt"
    save_private_key(key, int_key_path)
    save_cert(cert, int_cert_path)
    print(f"[PKI] Intermediate CA created → {int_cert_path}")
    return key, cert


def issue_user_cert(username: str, int_key, int_cert, validity_days: int = 365) -> tuple:
    """Issue a signing certificate for a staff member."""
    key = generate_ec_key()
    name = _build_name(username)
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(int_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .sign(int_key, hashes.SHA256())
    )

    user_dir = PKI_DIR / "users" / username
    user_dir.mkdir(parents=True, exist_ok=True)
    save_private_key(key, user_dir / "signing.key")
    save_cert(cert, user_dir / "signing.crt")
    print(f"[PKI] User cert issued for '{username}'")
    return key, cert


def build_crl(int_key, int_cert, revoked_serials: list[int]) -> CertificateRevocationList:
    """Build a Certificate Revocation List."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(int_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )
    for serial in revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(int_key, hashes.SHA256())
    (PKI_DIR / "crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    print(f"[PKI] CRL updated with {len(revoked_serials)} revocation(s)")
    return crl


# ─────────────────────────────────────────────────────────────────────────────
# Document Hashing & Digital Signatures
# ─────────────────────────────────────────────────────────────────────────────

def sha256_file(filepath: Path) -> str:
    """Return hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_document(filepath: Path, signing_key) -> bytes:
    """Sign a document with ECDSA and return the DER signature bytes."""
    digest = sha256_file(filepath).encode()
    sig = signing_key.sign(digest, ECDSA(hashes.SHA256()))
    sig_path = Path(str(filepath) + ".sig")
    sig_path.write_bytes(sig)
    print(f"[Crypto] Document signed → {sig_path.name}")
    return sig


def verify_document(filepath: Path, sig_bytes: bytes, public_key) -> bool:
    """Verify ECDSA signature and confirm file is untampered."""
    digest = sha256_file(filepath).encode()
    try:
        public_key.verify(sig_bytes, digest, ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def tamper_check(filepath: Path, stored_hash: str) -> bool:
    """Compare stored SHA-256 against current file hash."""
    return sha256_file(filepath) == stored_hash


# ─────────────────────────────────────────────────────────────────────────────
# Password Hashing (Argon2)
# ─────────────────────────────────────────────────────────────────────────────

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def hash_password(plaintext: str) -> str:
    return _ph.hash(plaintext)


def verify_password(hashed: str, plaintext: str) -> bool:
    try:
        return _ph.verify(hashed, plaintext)
    except argon2.exceptions.VerifyMismatchError:
        return False


def demo_hash_comparison():
    """Show how Argon2 beats MD5 for password storage."""
    import time
    pw = "P@ssw0rd123!"
    t0 = time.perf_counter()
    md5_hash = hashlib.md5(pw.encode()).hexdigest()
    md5_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    argon_hash = hash_password(pw)
    argon_time = time.perf_counter() - t0

    print(f"\n[Security Demo] MD5  ({md5_time*1000:.3f} ms): {md5_hash}")
    print(f"[Security Demo] Argon2 ({argon_time*1000:.0f} ms): {argon_hash[:60]}…")
    print("[Security Demo] Argon2 is intentionally slow → resistant to cracking\n")


# ─────────────────────────────────────────────────────────────────────────────
# Key Rotation Scheduler
# ─────────────────────────────────────────────────────────────────────────────

KEY_SCHEDULE_FILE = PKI_DIR / "key_schedule.json"


def init_key_schedule(username: str, rotation_days: int = 90):
    schedule = {}
    if KEY_SCHEDULE_FILE.exists():
        schedule = json.loads(KEY_SCHEDULE_FILE.read_text())
    next_rotation = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=rotation_days)
    ).isoformat()
    schedule[username] = {"next_rotation": next_rotation, "rotation_days": rotation_days}
    KEY_SCHEDULE_FILE.write_text(json.dumps(schedule, indent=2))


def check_key_rotations() -> list[str]:
    """Return list of usernames whose keys need rotation."""
    if not KEY_SCHEDULE_FILE.exists():
        return []
    schedule = json.loads(KEY_SCHEDULE_FILE.read_text())
    now = datetime.datetime.now(datetime.timezone.utc)
    due = []
    for user, info in schedule.items():
        next_rot = datetime.datetime.fromisoformat(info["next_rotation"])
        if now >= next_rot:
            due.append(user)
    return due


if __name__ == "__main__":
    print("=== PKI Manager Self-Test ===\n")
    root_key, root_cert = create_root_ca()
    int_key, int_cert = create_intermediate_ca(root_key, root_cert)
    user_key, user_cert = issue_user_cert("alice", int_key, int_cert)

    # Sign and verify a dummy document
    test_doc = PKI_DIR / "test_document.txt"
    test_doc.write_text("This is a confidential contract.")
    original_hash = sha256_file(test_doc)
    sig = sign_document(test_doc, user_key)
    print(f"[Test] Original hash: {original_hash}")
    print(f"[Test] Sig valid (clean): {verify_document(test_doc, sig, user_key.public_key())}")

    # Tamper with document
    test_doc.write_text("This is a TAMPERED contract!")
    print(f"[Test] Sig valid (tampered): {verify_document(test_doc, sig, user_key.public_key())}")
    print(f"[Test] Tamper check: {'TAMPERED' if not tamper_check(test_doc, original_hash) else 'OK'}")

    demo_hash_comparison()

    # CRL
    build_crl(int_key, int_cert, [user_cert.serial_number])

    # Key schedule
    init_key_schedule("alice")
    print(f"[PKI] Keys due for rotation: {check_key_rotations()}")
