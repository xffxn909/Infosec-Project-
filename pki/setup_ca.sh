#!/usr/bin/env bash
# =============================================================================
# setup_ca.sh — PKI Infrastructure Setup for SecureDocSystem
# =============================================================================
# WARNING: Passwords below are hardcoded for LAB/DEMO purposes only.
# In production, use a secrets manager or prompt interactively.
# ROOT_CA_PASS and INT_CA_PASS protect the CA private keys.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$SCRIPT_DIR"

ROOT_CA_PASS="pass:RootCA_Lab_Password_2024"
INT_CA_PASS="pass:IntCA_Lab_Password_2024"

ROOT_DIR="$PKI_DIR/root-ca"
INT_DIR="$PKI_DIR/intermediate-ca"
CERTS_DIR="$PKI_DIR/certs"
CRL_DIR="$PKI_DIR/crl"

echo "========================================"
echo "  SecureDocSystem PKI Setup"
echo "========================================"
echo ""

# ----------------------------------------------------------------------------
# 1. Create Directory Structure
# ----------------------------------------------------------------------------
echo "[1/7] Creating directory structure..."
mkdir -p "$ROOT_DIR"/{private,newcerts}
mkdir -p "$INT_DIR"/{private,newcerts,csr}
mkdir -p "$CERTS_DIR"
mkdir -p "$CRL_DIR"

chmod 700 "$ROOT_DIR/private" "$INT_DIR/private"

# OpenSSL database files
touch "$ROOT_DIR/index.txt" "$INT_DIR/index.txt"
echo "1000" > "$ROOT_DIR/serial"
echo "1000" > "$INT_DIR/serial"
echo "1000" > "$ROOT_DIR/crlnumber"
echo "1000" > "$INT_DIR/crlnumber"

echo "    Done."

# ----------------------------------------------------------------------------
# 2. Write Root CA OpenSSL Config
# ----------------------------------------------------------------------------
echo "[2/7] Writing OpenSSL configs..."

cat > "$ROOT_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ROOT_DIR
certs             = \$dir/newcerts
crl_dir           = $CRL_DIR
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/root_ca_key.pem
certificate       = \$dir/root_ca_cert.pem
crlnumber         = \$dir/crlnumber
crl               = $CRL_DIR/root_ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 365
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

countryName_default             = US
stateOrProvinceName_default     = California
localityName_default            = San Francisco
0.organizationName_default      = SecureDocSystem
organizationalUnitName_default  = Security Infrastructure
commonName_default              = SecureDocSystem Root CA

[ v3_ca ]
# Root CA extensions — CA:true, can sign certs and CRLs
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Intermediate CA — pathlen:0 means no further CAs below
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# End-entity user cert extensions
basicConstraints       = CA:false
nsCertType             = client, email
nsComment              = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ server_cert ]
# Server cert extensions
basicConstraints       = CA:false
nsCertType             = server
nsComment              = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ ocsp ]
basicConstraints       = CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, OCSPSigning
EOF

# Intermediate CA config (points to its own dir for signing)
cat > "$INT_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $INT_DIR
certs             = \$dir/newcerts
crl_dir           = $CRL_DIR
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/intermediate_ca_key.pem
certificate       = \$dir/intermediate_ca_cert.pem
crlnumber         = \$dir/crlnumber
crl               = $CRL_DIR/intermediate_ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 90
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 365
preserve          = no
policy            = policy_loose

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_intermediate_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints       = CA:false
nsCertType             = client, email
nsComment              = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ server_cert ]
basicConstraints       = CA:false
nsCertType             = server
nsComment              = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ ocsp ]
basicConstraints       = CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, OCSPSigning
EOF

echo "    Done."

# ----------------------------------------------------------------------------
# 3. Generate Root CA Key and Self-Signed Certificate
# ----------------------------------------------------------------------------
echo "[3/7] Generating Root CA..."

openssl genrsa \
    -aes256 \
    -passout "$ROOT_CA_PASS" \
    -out "$ROOT_DIR/private/root_ca_key.pem" \
    4096

chmod 400 "$ROOT_DIR/private/root_ca_key.pem"

openssl req \
    -config "$ROOT_DIR/openssl.cnf" \
    -key "$ROOT_DIR/private/root_ca_key.pem" \
    -passin "$ROOT_CA_PASS" \
    -new \
    -x509 \
    -days 3650 \
    -sha256 \
    -extensions v3_ca \
    -subj "/C=US/ST=California/L=San Francisco/O=SecureDocSystem/OU=Security Infrastructure/CN=SecureDocSystem Root CA" \
    -out "$ROOT_DIR/root_ca_cert.pem"

echo "    Root CA certificate created."
openssl x509 -noout -subject -dates -in "$ROOT_DIR/root_ca_cert.pem"

# ----------------------------------------------------------------------------
# 4. Generate Intermediate CA Key, CSR, and Signed Certificate
# ----------------------------------------------------------------------------
echo "[4/7] Generating Intermediate CA..."

openssl genrsa \
    -aes256 \
    -passout "$INT_CA_PASS" \
    -out "$INT_DIR/private/intermediate_ca_key.pem" \
    4096

chmod 400 "$INT_DIR/private/intermediate_ca_key.pem"

openssl req \
    -config "$INT_DIR/openssl.cnf" \
    -new \
    -sha256 \
    -key "$INT_DIR/private/intermediate_ca_key.pem" \
    -passin "$INT_CA_PASS" \
    -subj "/C=US/ST=California/L=San Francisco/O=SecureDocSystem/OU=Security Infrastructure/CN=SecureDocSystem Intermediate CA" \
    -out "$INT_DIR/csr/intermediate_ca.csr"

openssl ca \
    -config "$ROOT_DIR/openssl.cnf" \
    -extensions v3_intermediate_ca \
    -days 1825 \
    -notext \
    -md sha256 \
    -passin "$ROOT_CA_PASS" \
    -in "$INT_DIR/csr/intermediate_ca.csr" \
    -out "$INT_DIR/intermediate_ca_cert.pem" \
    -batch

chmod 444 "$INT_DIR/intermediate_ca_cert.pem"

echo "    Intermediate CA certificate created."
openssl x509 -noout -subject -dates -in "$INT_DIR/intermediate_ca_cert.pem"

# Verify intermediate cert was signed by root
openssl verify -CAfile "$ROOT_DIR/root_ca_cert.pem" "$INT_DIR/intermediate_ca_cert.pem"
echo "    Intermediate CA verification: OK"

# ----------------------------------------------------------------------------
# 5. Issue Server Certificate for localhost / securedocs.local
# ----------------------------------------------------------------------------
echo "[5/7] Issuing server certificate..."

SERVER_KEY="$CERTS_DIR/server_key.pem"
SERVER_CSR="$CERTS_DIR/server.csr"
SERVER_CERT="$CERTS_DIR/server.pem"

openssl genrsa -out "$SERVER_KEY" 2048
chmod 400 "$SERVER_KEY"

# Write SAN extension config for the server cert
cat > "$CERTS_DIR/server_san.cnf" <<EOF
[req]
default_bits        = 2048
distinguished_name  = req_distinguished_name
req_extensions      = req_ext
prompt              = no

[req_distinguished_name]
C  = US
ST = California
L  = San Francisco
O  = SecureDocSystem
OU = Web Services
CN = securedocs.local

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = securedocs.local
IP.1  = 127.0.0.1

[server_cert]
basicConstraints       = CA:false
nsCertType             = server
nsComment              = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names
EOF

openssl req \
    -config "$CERTS_DIR/server_san.cnf" \
    -key "$SERVER_KEY" \
    -new \
    -sha256 \
    -out "$SERVER_CSR"

# Sign with intermediate CA, using SAN extension config
openssl x509 \
    -req \
    -in "$SERVER_CSR" \
    -CA "$INT_DIR/intermediate_ca_cert.pem" \
    -CAkey "$INT_DIR/private/intermediate_ca_key.pem" \
    -passin "$INT_CA_PASS" \
    -CAserial "$INT_DIR/serial" \
    -days 365 \
    -sha256 \
    -extfile "$CERTS_DIR/server_san.cnf" \
    -extensions server_cert \
    -out "$SERVER_CERT"

echo "    Server certificate created."
openssl x509 -noout -subject -dates -ext subjectAltName -in "$SERVER_CERT"

# ----------------------------------------------------------------------------
# 6. Create Certificate Chain File
# ----------------------------------------------------------------------------
echo "[6/7] Creating certificate chain..."
cat "$INT_DIR/intermediate_ca_cert.pem" "$ROOT_DIR/root_ca_cert.pem" > "$CERTS_DIR/chain.pem"
echo "    Chain file created: pki/certs/chain.pem (Intermediate + Root)"

# Verify server cert against full chain
openssl verify \
    -CAfile "$ROOT_DIR/root_ca_cert.pem" \
    -untrusted "$INT_DIR/intermediate_ca_cert.pem" \
    "$SERVER_CERT"
echo "    Server certificate chain verification: OK"

# ----------------------------------------------------------------------------
# 7. Generate Initial CRL
# ----------------------------------------------------------------------------
echo "[7/7] Generating initial CRLs..."

openssl ca \
    -config "$ROOT_DIR/openssl.cnf" \
    -gencrl \
    -passin "$ROOT_CA_PASS" \
    -out "$CRL_DIR/root_ca.crl.pem"

openssl ca \
    -config "$INT_DIR/openssl.cnf" \
    -gencrl \
    -passin "$INT_CA_PASS" \
    -out "$CRL_DIR/intermediate_ca.crl.pem"

# Combine CRLs
cat "$CRL_DIR/intermediate_ca.crl.pem" "$CRL_DIR/root_ca.crl.pem" > "$CRL_DIR/chain.crl.pem"
echo "    CRLs generated."

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
echo ""
echo "========================================"
echo "  PKI Setup Complete — Summary"
echo "========================================"
echo ""
echo "Directory layout:"
echo "  pki/"
echo "  ├── root-ca/"
echo "  │   ├── private/root_ca_key.pem        (ENCRYPTED, 4096-bit RSA)"
echo "  │   ├── root_ca_cert.pem               (Self-signed, 10 years)"
echo "  │   ├── index.txt                      (Certificate database)"
echo "  │   └── openssl.cnf"
echo "  ├── intermediate-ca/"
echo "  │   ├── private/intermediate_ca_key.pem (ENCRYPTED, 4096-bit RSA)"
echo "  │   ├── intermediate_ca_cert.pem        (Signed by Root CA, 5 years)"
echo "  │   └── openssl.cnf"
echo "  ├── certs/"
echo "  │   ├── server_key.pem                  (2048-bit RSA, unencrypted)"
echo "  │   ├── server.pem                      (Signed by Intermediate CA, 1 year)"
echo "  │   └── chain.pem                       (Intermediate + Root bundle)"
echo "  └── crl/"
echo "      ├── root_ca.crl.pem"
echo "      ├── intermediate_ca.crl.pem"
echo "      └── chain.crl.pem"
echo ""
echo "Next steps:"
echo "  - Issue user certs:    ./issue_user_cert.sh <user_id> <email>"
echo "  - Revoke a cert:       ./revoke_cert.sh <cert_path>"
echo "  - Deploy server cert:  copy certs/server.pem + certs/server_key.pem to nginx"
echo "  - Trust Root CA:       install root-ca/root_ca_cert.pem in OS/browser trust store"
echo ""
echo "SECURITY NOTE: In production, move root-ca/private/ to an air-gapped machine"
echo "and delete it from this system after issuing the intermediate CA certificate."
