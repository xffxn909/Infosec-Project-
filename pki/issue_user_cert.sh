#!/usr/bin/env bash
# =============================================================================
# issue_user_cert.sh — Issue RSA signing certificate for a system user
# =============================================================================
# Usage: ./issue_user_cert.sh <user_id> <email>
# Example: ./issue_user_cert.sh 42 alice@example.com
#
# Outputs:
#   pki/certs/user_<user_id>.pem       — user certificate
#   pki/certs/user_<user_id>_key.pem   — user private key (unencrypted)
#
# NOTE: Password below is for LAB use only. In production, protect user keys
# with per-user passphrases or a hardware token.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$SCRIPT_DIR"
INT_DIR="$PKI_DIR/intermediate-ca"
CERTS_DIR="$PKI_DIR/certs"

# Intermediate CA passphrase (LAB only)
INT_CA_PASS="pass:IntCA_Lab_Password_2024"

# ---- Argument validation ----
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <user_id> <email>"
    echo "Example: $0 42 alice@example.com"
    exit 1
fi

USER_ID="$1"
EMAIL="$2"

# Basic email format check
if [[ ! "$EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
    echo "ERROR: Invalid email address: $EMAIL"
    exit 1
fi

# Check PKI is initialized
if [[ ! -f "$INT_DIR/intermediate_ca_cert.pem" ]]; then
    echo "ERROR: Intermediate CA not found. Run setup_ca.sh first."
    exit 1
fi

USER_KEY="$CERTS_DIR/user_${USER_ID}_key.pem"
USER_CSR="$CERTS_DIR/user_${USER_ID}.csr"
USER_CERT="$CERTS_DIR/user_${USER_ID}.pem"
USER_SAN_CNF="$CERTS_DIR/user_${USER_ID}_san.cnf"

echo "========================================"
echo "  Issuing user certificate"
echo "  User ID : $USER_ID"
echo "  Email   : $EMAIL"
echo "========================================"

# ---- Generate RSA 2048 user key ----
echo "[1/4] Generating RSA 2048 key..."
openssl genrsa -out "$USER_KEY" 2048
chmod 400 "$USER_KEY"
echo "    Key: $USER_KEY"

# ---- Write SAN config for the CSR ----
echo "[2/4] Creating CSR with SAN email extension..."
cat > "$USER_SAN_CNF" <<EOF
[req]
default_bits        = 2048
distinguished_name  = req_distinguished_name
req_extensions      = req_ext
prompt              = no

[req_distinguished_name]
C  = US
ST = California
O  = SecureDocSystem
OU = Users
CN = User $USER_ID
emailAddress = $EMAIL

[req_ext]
subjectAltName = email:$EMAIL

[usr_cert]
basicConstraints       = CA:false
nsCertType             = client, email
nsComment              = "SecureDocSystem User Signing Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection
subjectAltName         = email:$EMAIL
EOF

# ---- Generate CSR ----
openssl req \
    -config "$USER_SAN_CNF" \
    -key "$USER_KEY" \
    -new \
    -sha256 \
    -out "$USER_CSR"
echo "    CSR created."

# ---- Sign with Intermediate CA ----
echo "[3/4] Signing certificate with Intermediate CA..."
openssl x509 \
    -req \
    -in "$USER_CSR" \
    -CA "$INT_DIR/intermediate_ca_cert.pem" \
    -CAkey "$INT_DIR/private/intermediate_ca_key.pem" \
    -passin "$INT_CA_PASS" \
    -CAserial "$INT_DIR/serial" \
    -days 365 \
    -sha256 \
    -extfile "$USER_SAN_CNF" \
    -extensions usr_cert \
    -out "$USER_CERT"
echo "    Certificate signed."

# ---- Verify the certificate ----
echo "[4/4] Verifying certificate..."
ROOT_CERT="$PKI_DIR/root-ca/root_ca_cert.pem"
INT_CERT="$INT_DIR/intermediate_ca_cert.pem"
openssl verify -CAfile "$ROOT_CERT" -untrusted "$INT_CERT" "$USER_CERT"

# ---- Cleanup temp files ----
rm -f "$USER_CSR" "$USER_SAN_CNF"

# ---- Summary ----
echo ""
echo "========================================"
echo "  User Certificate Issued"
echo "========================================"
openssl x509 -noout -subject -dates -email -in "$USER_CERT"
echo ""
echo "Files:"
echo "  Certificate : $USER_CERT"
echo "  Private Key : $USER_KEY"
echo ""
echo "SECURITY NOTE: Protect $USER_KEY — this is the user's signing key."
echo "In production, deliver it via encrypted channel or store in HSM/token."
