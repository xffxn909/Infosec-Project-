# PKI Infrastructure — SecureDocSystem

This directory contains the Public Key Infrastructure (PKI) for the SecureDocSystem Secure Document Management & E-Signature System.

---

## PKI Hierarchy

```
Root CA (Self-Signed, 10 years)
└── Intermediate CA (pathlen:0, 5 years)
    ├── Server Certificate (localhost / securedocs.local, 1 year)
    └── User Signing Certificates (per user, 1 year)
```

| Component | Key Size | Validity | Signed By |
|-----------|----------|----------|-----------|
| Root CA | RSA 4096 | 10 years | Self-signed |
| Intermediate CA | RSA 4096 | 5 years | Root CA |
| Server Certificate | RSA 2048 | 1 year | Intermediate CA |
| User Signing Cert | RSA 2048 | 1 year | Intermediate CA |

**Why two-tier CA?**  
The Root CA's private key should be kept offline (air-gapped). Day-to-day certificate issuance is handled by the Intermediate CA. If the Intermediate CA is compromised, it can be revoked by the Root CA and replaced without re-issuing the Root.

---

## Directory Layout

```
pki/
├── setup_ca.sh               # PKI initialization script
├── issue_user_cert.sh        # Issue user signing certificates
├── revoke_cert.sh            # Revoke a certificate + regenerate CRL
├── README.md                 # This file
├── root-ca/
│   ├── private/
│   │   └── root_ca_key.pem  # Root CA private key (AES-256 encrypted)
│   ├── root_ca_cert.pem     # Root CA certificate (self-signed)
│   ├── index.txt            # OpenSSL certificate database
│   ├── serial               # Next serial number
│   ├── crlnumber            # CRL sequence counter
│   └── openssl.cnf          # Root CA OpenSSL configuration
├── intermediate-ca/
│   ├── private/
│   │   └── intermediate_ca_key.pem  # Intermediate CA key (AES-256 encrypted)
│   ├── intermediate_ca_cert.pem     # Intermediate CA certificate
│   ├── index.txt
│   ├── serial
│   ├── crlnumber
│   └── openssl.cnf
├── certs/
│   ├── server.pem           # Server TLS certificate
│   ├── server_key.pem       # Server TLS private key
│   ├── chain.pem            # Intermediate + Root bundle (for nginx)
│   └── user_<id>.pem        # User signing certificates (issued as needed)
└── crl/
    ├── root_ca.crl.pem      # Root CA Certificate Revocation List
    ├── intermediate_ca.crl.pem  # Intermediate CA CRL
    └── chain.crl.pem        # Combined CRL
```

---

## Setup — Running `setup_ca.sh`

> **Prerequisites**: OpenSSL must be installed (`openssl version`).

```bash
cd /Users/mohsinzia/InfosecProject/pki
bash setup_ca.sh
```

This will:
1. Create the directory structure above
2. Generate the Root CA key (RSA 4096, AES-256 encrypted) and self-signed certificate
3. Generate the Intermediate CA key and CSR, sign it with the Root CA
4. Issue a server TLS certificate with SANs: `localhost`, `securedocs.local`, `127.0.0.1`
5. Create `certs/chain.pem` (Intermediate + Root for TLS chain)
6. Generate initial CRLs for both CAs
7. Print a summary

**Lab passwords** (hardcoded for demo — change for any real deployment):
- Root CA key passphrase: `RootCA_Lab_Password_2024`
- Intermediate CA key passphrase: `IntCA_Lab_Password_2024`

---

## Issuing User Signing Certificates

```bash
cd /Users/mohsinzia/InfosecProject/pki
bash issue_user_cert.sh <user_id> <email>

# Example:
bash issue_user_cert.sh 42 alice@example.com
```

Output files:
- `pki/certs/user_42.pem` — the user's X.509 certificate
- `pki/certs/user_42_key.pem` — the user's RSA private key (unencrypted, protect carefully)

The certificate includes the user's email as a `subjectAltName` and is valid for `emailProtection` and `clientAuth` extended key usage, making it suitable for document signing and email S/MIME.

---

## Revoking Certificates

```bash
cd /Users/mohsinzia/InfosecProject/pki
bash revoke_cert.sh pki/certs/user_42.pem
```

This:
1. Marks the certificate as revoked in `intermediate-ca/index.txt`
2. Regenerates `crl/intermediate_ca.crl.pem`
3. Regenerates `crl/root_ca.crl.pem`
4. Rebuilds `crl/chain.crl.pem`

**After revocation**, distribute the updated CRL to all relying parties (e.g., place `intermediate_ca.crl.pem` at your OCSP/CRL distribution point URL).

**Verify a cert against the CRL:**
```bash
openssl verify \
  -CAfile pki/root-ca/root_ca_cert.pem \
  -untrusted pki/intermediate-ca/intermediate_ca_cert.pem \
  -crl_check \
  -CRLfile pki/crl/intermediate_ca.crl.pem \
  pki/certs/user_42.pem
```

---

## CRL and OCSP Notes

### Certificate Revocation List (CRL)

A CRL is a signed list of revoked certificate serial numbers, published by the CA. Clients download it periodically and check whether a certificate's serial is listed.

| CA | CRL File | Validity |
|----|----------|----------|
| Root CA | `crl/root_ca.crl.pem` | 365 days |
| Intermediate CA | `crl/intermediate_ca.crl.pem` | 90 days |

**CRL Distribution Point**: In a production setup, include a `crlDistributionPoints` extension in issued certificates pointing to a publicly accessible URL (e.g., `http://pki.yourdomain.com/crl/intermediate.crl`). Update the OpenSSL configs accordingly.

### OCSP (Online Certificate Status Protocol)

OCSP allows real-time certificate status checks (unlike CRLs, which are downloaded in bulk). To add OCSP:

1. Generate an OCSP responder signing certificate (with `OCSPSigning` extended key usage).
2. Run an OCSP responder: `openssl ocsp -index intermediate-ca/index.txt -port 2560 -rsigner ocsp.pem -rkey ocsp_key.pem -CA intermediate-ca/intermediate_ca_cert.pem`
3. Add `authorityInfoAccess = OCSP;URI:http://ocsp.yourdomain.com:2560` to issued cert configs.

> **Note**: For this lab, only CRL-based revocation is implemented. OCSP would require a publicly reachable server.

---

## Security Notes

### Root CA Key — Keep It Offline

> [!CAUTION]
> The Root CA private key (`root-ca/private/root_ca_key.pem`) is the trust anchor for the entire PKI. In production:
> - Store it on an **air-gapped machine** or **Hardware Security Module (HSM)**.
> - After issuing the Intermediate CA certificate, **delete** the Root CA key from the online system.
> - Bring the offline Root CA online only to issue/renew Intermediate CAs or update the Root CRL.

### Key Rotation Policy

| Certificate | Rotation Interval | Action |
|-------------|-------------------|--------|
| Root CA | 10 years | Plan replacement 1–2 years before expiry; overlap trust periods |
| Intermediate CA | 5 years | Issue new Intermediate CA from Root CA; revoke old one |
| Server TLS cert | 1 year (or sooner) | Automate with cron / Let's Encrypt if applicable |
| User signing cert | 1 year | Re-issue via `issue_user_cert.sh` on renewal |

### Additional Hardening

- **Private key permissions**: All private keys should be `chmod 400` (readable only by owner).
- **Passphrase protection**: CA private keys are AES-256 encrypted. Store passphrases in a secrets manager (e.g., HashiCorp Vault) — not in scripts.
- **Certificate pinning**: Consider pinning the Root CA certificate in the application to prevent MITM with rogue CAs.
- **Audit logging**: Log all certificate issuance and revocation events with timestamps, operator identity, and certificate serial numbers.
- **SAN-only**: Modern TLS requires SANs; the `CN` field alone is no longer trusted by modern browsers.
