"""Cryptographic helpers for document signing and verification."""

import base64
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def compute_sha256(filepath: str) -> str:
    """Compute the SHA-256 hex digest of a file on disk.

    Reads the file in 64 KB chunks to handle large files without exhausting
    available memory.

    Args:
        filepath: Absolute or relative path to the file.

    Returns:
        Lowercase hexadecimal SHA-256 digest string (64 characters).
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def sign_document(filepath: str, private_key_pem: bytes) -> str:
    """Sign the SHA-256 hash of a file with an RSA private key.

    Uses RSA-PSS with SHA-256 as the hash algorithm, which is the recommended
    padding scheme for new applications (superior to PKCS#1 v1.5).

    Args:
        filepath: Path to the file whose hash will be signed.
        private_key_pem: PEM-encoded RSA private key bytes.

    Returns:
        Base-64 encoded signature string suitable for JSON serialisation.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend(),
    )

    file_hash = bytes.fromhex(compute_sha256(filepath))

    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode("utf-8")


def verify_signature(filepath: str, signature_b64: str, public_key_pem: bytes) -> bool:
    """Verify an RSA-PSS signature against a file.

    Re-computes the SHA-256 hash of the file at ``filepath`` and checks it
    against the provided signature using the supplied public key.

    Args:
        filepath: Path to the file to verify.
        signature_b64: Base-64 encoded signature (as returned by sign_document).
        public_key_pem: PEM-encoded RSA public key bytes.

    Returns:
        True when the signature is valid; False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend(),
        )

        file_hash = bytes.fromhex(compute_sha256(filepath))
        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, Exception):
        return False


def generate_key_pair() -> tuple[bytes, bytes]:
    """Generate a new RSA-2048 key pair.

    Returns:
        A tuple ``(private_pem, public_pem)`` where both elements are
        PEM-encoded byte strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem
