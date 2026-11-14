#!/usr/bin/env bash
# =============================================================================
# revoke_cert.sh — Revoke a certificate and regenerate the CRL
# =============================================================================
# Usage: ./revoke_cert.sh <cert_path>
# Example: ./revoke_cert.sh pki/certs/user_42.pem
#
# NOTE: Password below is for LAB use only.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$SCRIPT_DIR"
INT_DIR="$PKI_DIR/intermediate-ca"
ROOT_DIR="$PKI_DIR/root-ca"
CRL_DIR="$PKI_DIR/crl"

# CA passphrases (LAB only)
INT_CA_PASS="pass:IntCA_Lab_Password_2024"
ROOT_CA_PASS="pass:RootCA_Lab_Password_2024"

# ---- Argument validation ----
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <cert_path>"
    echo "Example: $0 pki/certs/user_42.pem"
    exit 1
fi

CERT_PATH="$1"

if [[ ! -f "$CERT_PATH" ]]; then
    echo "ERROR: Certificate not found: $CERT_PATH"
    exit 1
fi

if [[ ! -f "$INT_DIR/intermediate_ca_cert.pem" ]]; then
    echo "ERROR: Intermediate CA not found. Run setup_ca.sh first."
    exit 1
fi

echo "========================================"
echo "  Certificate Revocation"
echo "========================================"
echo ""
echo "Certificate to revoke:"
openssl x509 -noout -subject -serial -dates -in "$CERT_PATH"
echo ""

# Safety prompt — confirm revocation
read -r -p "Are you sure you want to revoke this certificate? [yes/no]: " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Revocation cancelled."
    exit 0
fi

# ---- Determine which CA issued this cert ----
# Check if it was issued by the Intermediate CA (most common case)
ISSUER=$(openssl x509 -noout -issuer -in "$CERT_PATH" | sed 's/issuer= //')
INT_SUBJECT=$(openssl x509 -noout -subject -in "$INT_DIR/intermediate_ca_cert.pem" | sed 's/subject= //')

echo "[1/3] Revoking certificate with Intermediate CA..."
openssl ca \
    -config "$INT_DIR/openssl.cnf" \
    -revoke "$CERT_PATH" \
    -passin "$INT_CA_PASS" \
    -batch

echo "    Certificate revoked."

# ---- Regenerate Intermediate CA CRL ----
echo "[2/3] Regenerating Intermediate CA CRL..."
openssl ca \
    -config "$INT_DIR/openssl.cnf" \
    -gencrl \
    -passin "$INT_CA_PASS" \
    -out "$CRL_DIR/intermediate_ca.crl.pem"

echo "    Intermediate CRL updated: $CRL_DIR/intermediate_ca.crl.pem"

# ---- Regenerate Root CA CRL ----
echo "[3/3] Regenerating Root CA CRL..."
openssl ca \
    -config "$ROOT_DIR/openssl.cnf" \
    -gencrl \
    -passin "$ROOT_CA_PASS" \
    -out "$CRL_DIR/root_ca.crl.pem"

# ---- Rebuild combined CRL ----
cat "$CRL_DIR/intermediate_ca.crl.pem" "$CRL_DIR/root_ca.crl.pem" > "$CRL_DIR/chain.crl.pem"
echo "    Root CRL updated and chain CRL rebuilt."

# ---- Show CRL contents ----
echo ""
echo "========================================"
echo "  Updated CRL Summary"
echo "========================================"
openssl crl -noout -text -in "$CRL_DIR/intermediate_ca.crl.pem" | \
    grep -E "(Last Update|Next Update|Serial Number)" | head -20

echo ""
echo "Revoked certificates in Intermediate CA database:"
grep "^R" "$INT_DIR/index.txt" | awk '{print "  Serial:", $3, "| Revoked:", $2, "| Subject:", $6}' || true

echo ""
echo "IMPORTANT: Distribute the updated CRL to all relying parties."
echo "CRL location: $CRL_DIR/intermediate_ca.crl.pem"
echo ""
echo "To verify a cert against the CRL:"
echo "  openssl verify -CAfile pki/root-ca/root_ca_cert.pem \\"
echo "                 -untrusted pki/intermediate-ca/intermediate_ca_cert.pem \\"
echo "                 -crl_check -CRLfile $CRL_DIR/intermediate_ca.crl.pem \\"
echo "                 <cert_path>"
