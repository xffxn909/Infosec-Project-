# Standalone Secure Document Management System

**Author:** Syed Muhammad Ali Hassan (549075)

A self-contained, single-machine version of the Secure Document Management & E-Signature System.  
Runs entirely from Python — no Docker, Node.js, or external CA tools required.

## Quick Start

```bash
cd standalone
pip install -r requirements.txt
python pki_manager.py        # PKI self-test: Root CA → Intermediate CA → User cert → Sign/Verify → CRL
python risk_assessment.py    # Generate NIST SP 800-30 risk report + heat maps
python backup_service.py     # Backup/restore SLA test + firewall rules
python create_user.py        # Interactive CLI user creation with optional MFA
python app.py                # Start the web app at http://127.0.0.1:5000
```

Default admin credentials: `admin` / `Admin@1234`

## Modules Covered

| Module | Component | File |
|--------|-----------|------|
| CIA – Confidentiality | Argon2id passwords, RBAC, TOTP MFA | `auth.py` |
| CIA – Integrity | SHA-256 hashing, RSA-PSS signing, audit log | `document_service.py`, `pki_manager.py` |
| CIA – Availability | Automated backup/restore, firewall rules | `backup_service.py` |
| Cryptography | Full PKI (Root CA, Intermediate CA, CRL), MD5 vs Argon2 demo | `pki_manager.py` |
| Risk Assessment | NIST SP 800-30 report, 5×5 heat map, policies | `risk_assessment.py` |
