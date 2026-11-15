#!/usr/bin/env python3
"""
hash_verify.py — File integrity verification using SHA-256 and RSA signatures.

Usage:
    python hash_verify.py <filepath>
        Computes and prints the SHA-256 hash of the file.

    python hash_verify.py <filepath> --signature <sig_file> --pubkey <pubkey_file>
        Also verifies the RSA signature against the file's hash.

    python hash_verify.py --demo <filepath>
        Tamper-detection demo: hashes the file, modifies a byte copy,
        recomputes the hash, and shows "TAMPERED" detection.
"""

import argparse
import hashlib
import os
import shutil
import sys
import tempfile


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def compute_sha256(filepath: str) -> str:
    """Return the hex SHA-256 digest of the file at *filepath*."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_rsa_signature(filepath: str, sig_file: str, pubkey_file: str) -> bool:
    """
    Verify an RSA-PSS (or PKCS1v15) signature over the SHA-256 hash of the file.
    Returns True if valid, False otherwise.
    Requires the `cryptography` library (pip install cryptography).
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        print("  [!] 'cryptography' library not found. Install with: pip install cryptography")
        return False

    # Load public key
    with open(pubkey_file, "rb") as f:
        pubkey_data = f.read()
    try:
        public_key = serialization.load_pem_public_key(pubkey_data)
    except Exception as e:
        print(f"  [!] Failed to load public key: {e}")
        return False

    # Load signature
    with open(sig_file, "rb") as f:
        signature = f.read()

    # Compute file digest
    digest = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    file_hash = digest.digest()

    # Try PSS first, then fall back to PKCS1v15
    for pad in [
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        padding.PKCS1v15(),
    ]:
        try:
            public_key.verify(signature, file_hash, pad, hashes.SHA256())
            return True
        except InvalidSignature:
            continue
        except Exception:
            continue

    return False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_verify(filepath: str, sig_file: str | None, pubkey_file: str | None) -> int:
    """Standard verify mode."""
    if not os.path.isfile(filepath):
        print(f"ERROR: File not found: {filepath}", file=sys.stderr)
        return 1

    file_hash = compute_sha256(filepath)
    filename = os.path.basename(filepath)

    print("=" * 60)
    print("  File Integrity Report")
    print("=" * 60)
    print(f"  File     : {filename}")
    print(f"  Path     : {os.path.abspath(filepath)}")
    print(f"  Size     : {os.path.getsize(filepath):,} bytes")
    print(f"  SHA-256  : {file_hash}")

    if sig_file and pubkey_file:
        if not os.path.isfile(sig_file):
            print(f"  ERROR: Signature file not found: {sig_file}", file=sys.stderr)
            return 1
        if not os.path.isfile(pubkey_file):
            print(f"  ERROR: Public key file not found: {pubkey_file}", file=sys.stderr)
            return 1

        valid = verify_rsa_signature(filepath, sig_file, pubkey_file)
        status = "✅ VALID" if valid else "❌ INVALID"
        print(f"  Signature: {status}")
        print("=" * 60)
        return 0 if valid else 2
    elif sig_file or pubkey_file:
        print("  Signature: ⚠️  NOT PROVIDED (need both --signature and --pubkey)")
    else:
        print("  Signature: — NOT PROVIDED")

    print("=" * 60)
    return 0


def cmd_demo(filepath: str) -> int:
    """Tamper-detection demo mode."""
    if not os.path.isfile(filepath):
        print(f"ERROR: File not found: {filepath}", file=sys.stderr)
        return 1

    filename = os.path.basename(filepath)

    print("=" * 60)
    print("  Tamper-Detection Demo")
    print("=" * 60)
    print(f"  Original file: {filename}")

    # Step 1: Hash original
    original_hash = compute_sha256(filepath)
    print(f"\n  [Step 1] Original SHA-256:")
    print(f"           {original_hash}")

    # Step 2: Create a tampered copy (flip one byte)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tampered") as tmp:
        shutil.copy2(filepath, tmp.name)
        tampered_path = tmp.name

    with open(tampered_path, "r+b") as f:
        # Modify the first non-zero byte (or byte at offset 0 if file is non-empty)
        content = bytearray(f.read())
        if len(content) == 0:
            print("\n  [!] File is empty — cannot demonstrate tampering.")
            os.unlink(tampered_path)
            return 1
        # XOR byte at index 0 with 0xFF (flip all bits)
        flip_index = min(10, len(content) - 1)  # offset 10 or last byte
        original_byte = content[flip_index]
        content[flip_index] = original_byte ^ 0xFF
        f.seek(0)
        f.write(content)

    tampered_hash = compute_sha256(tampered_path)
    os.unlink(tampered_path)

    print(f"\n  [Step 2] One byte modified at offset {flip_index}:")
    print(f"           Original byte : 0x{original_byte:02X}")
    print(f"           Modified byte : 0x{(original_byte ^ 0xFF):02X}")
    print(f"\n  [Step 3] Tampered copy SHA-256:")
    print(f"           {tampered_hash}")

    # Step 3: Compare
    if original_hash == tampered_hash:
        print("\n  Result : ⚠️  Hashes match (unexpected — hash collision?)")
    else:
        print("\n  Result : 🚨 TAMPERED — Hashes DO NOT match!")
        print(f"\n  Diff   : ")
        for i, (a, b) in enumerate(zip(original_hash, tampered_hash)):
            if a != b:
                print(f"           Position {i}: '{a}' → '{b}'")
                break
        print(f"\n  Even a single-bit change produces a completely different hash.")
        print(f"  SHA-256's avalanche effect guarantees tamper detection.")

    print("=" * 60)
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="File integrity verification via SHA-256 and RSA signature.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Positional (optional so --demo can be first)
    parser.add_argument(
        "filepath",
        nargs="?",
        help="Path to the file to verify (or demo file when --demo is set).",
    )
    parser.add_argument(
        "--signature", "-s",
        metavar="SIG_FILE",
        help="Path to the RSA signature file (binary).",
    )
    parser.add_argument(
        "--pubkey", "-k",
        metavar="PUBKEY_FILE",
        help="Path to the PEM-encoded RSA public key file.",
    )
    parser.add_argument(
        "--demo", "-d",
        metavar="FILEPATH",
        help="Run tamper-detection demo on the given file.",
    )

    args = parser.parse_args()

    if args.demo:
        return cmd_demo(args.demo)

    if not args.filepath:
        parser.print_help()
        return 1

    return cmd_verify(args.filepath, args.signature, args.pubkey)


if __name__ == "__main__":
    sys.exit(main())
