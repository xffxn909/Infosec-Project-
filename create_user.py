"""
create_user.py
==============
Command-line tool to create users directly in the database.
Run this from the project folder WITHOUT needing to start the web app.

Usage:
    python create_user.py

It will ask for username, password, and role interactively.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import init_db, get_user, create_user, update_user_cert
from pki_manager import hash_password, load_private_key, load_cert, PKI_DIR
from auth import generate_totp_secret, get_totp_uri

def main():
    print("=" * 50)
    print("   SecureDoc – Create New User")
    print("=" * 50)

    init_db()

    username = input("\nEnter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    if get_user(username):
        print(f"User '{username}' already exists!")
        return

    password = input("Enter password: ").strip()
    if not password:
        print("Password cannot be empty.")
        return

    print("\nSelect role:")
    print("  1. staff   (can upload and sign own documents)")
    print("  2. manager (can view all documents and audit log)")
    print("  3. admin   (full access)")
    role_choice = input("Enter 1, 2 or 3 [default: 1]: ").strip() or "1"
    role_map = {"1": "staff", "2": "manager", "3": "admin"}
    role = role_map.get(role_choice, "staff")

    enable_mfa = input("\nEnable MFA (TOTP)? y/n [default: n]: ").strip().lower()
    totp_secret = generate_totp_secret() if enable_mfa == "y" else None

    # Hash password
    pw_hash = hash_password(password)

    # Issue signing certificate if PKI exists
    int_key_path = PKI_DIR / "intermediate_ca.key"
    int_cert_path = PKI_DIR / "intermediate_ca.crt"
    cert_issued = False

    if int_key_path.exists() and int_cert_path.exists():
        from pki_manager import issue_user_cert
        int_key = load_private_key(int_key_path)
        int_cert = load_cert(int_cert_path)
        issue_user_cert(username, int_key, int_cert)
        cert_issued = True

    # Save to DB
    create_user(username, pw_hash, role=role, totp_secret=totp_secret)
    if cert_issued:
        update_user_cert(username, username + "-cert")

    print(f"\n✅ User '{username}' created successfully!")
    print(f"   Role     : {role}")
    print(f"   Password : {password}")
    print(f"   Cert     : {'Issued ✅' if cert_issued else 'Skipped (no PKI found)'}")

    if totp_secret:
        uri = get_totp_uri(totp_secret, username)
        print(f"\n   MFA enabled! Scan this URI with Google Authenticator:")
        print(f"   {uri}")
        print(f"\n   Or use this secret directly in an Authenticator app:")
        print(f"   {totp_secret}")
    else:
        print(f"   MFA      : Disabled (leave blank at login)")

    print("\nYou can now log in at http://127.0.0.1:5000")

if __name__ == "__main__":
    main()
