# Standalone Secure Document Management System

**Original Author:** Syed Muhammad Ali Hassan (549075)  
**Refactored & Integrated by:** Team InfoSec

A self-contained, single-machine lightweight version of the Secure Document Management & E-Signature System.  
Runs directly with Python and SQLite — no Docker, PostgreSQL, or Node.js required.

## Directory Structure

```
standalone/
├── app.py                  # Flask web server (routes, auth helpers, lifecycle)
├── auth.py                 # Argon2id password hashing, TOTP MFA, session management
├── database.py             # SQLite data access layer (users, documents, audit logs)
├── document_service.py     # Document upload, SHA-256 fingerprinting, digital signing & verification
├── backup_service.py       # Daily backup archive creation & SLA restore testing
├── pki_manager.py          # Cryptographic operations, CA hierarchy, cert issuance & CRL
├── risk_assessment.py      # NIST SP 800-30 risk calculator, matrices & report generator
├── create_user.py          # Interactive CLI tool for manual user creation & cert enrollment
├── requirements.txt        # Lightweight dependencies (Flask, cryptography, argon2-cffi, pyotp)
├── templates/              # Structured Jinja2 HTML templates
│   ├── base.html           # Unified base layout, responsive CSS, and navbar
│   ├── login.html          # Sign-in & TOTP MFA form
│   ├── dashboard.html      # Metrics overview (total, signed, alerts) & recent docs
│   ├── documents.html      # Upload form & document repository table
│   ├── verify.html         # Cryptographic verification & tamper check report
│   ├── audit.html          # Immutable system audit log viewer
│   ├── admin.html          # User administration, cert revocation & hash comparison demo
│   ├── backups.html        # On-demand backup creation & timed restore drills
│   └── risk.html           # NIST SP 800-30 register, treatment plans & policy viewer
├── pki/                    # CA certificates and CRL (private keys excluded from git)
├── uploads/                # Isolated document storage (.gitkeep)
└── risk_reports/           # Generated assessment reports (.gitkeep)
```

## Quick Start

```bash
# 1. Navigate to standalone directory and install dependencies
cd standalone
pip install -r requirements.txt

# 2. Run cryptographic PKI self-test
python pki_manager.py

# 3. Generate NIST SP 800-30 risk assessment report
python risk_assessment.py

# 4. Verify backup & restore SLA drill
python backup_service.py

# 5. Start the web application
python app.py
```

Then visit **http://127.0.0.1:5000** in your browser.  
Default Admin Credentials: `admin` / `Admin@1234` *(prompted to change upon production use)*.

## Security Controls Implemented

| Control | Mechanism | Implementation File |
|---|---|---|
| **Confidentiality** | Argon2id memory-hard password hashing, TOTP MFA, RBAC (Staff / Manager / Admin) | `auth.py`, `templates/login.html` |
| **Integrity** | SHA-256 cryptographic hashing, ECDSA/RSA digital signing, immutable SQLite audit trails | `document_service.py`, `database.py` |
| **Availability** | Automated backup archives, timed restore drills (RTO < 1 hr SLA target), rate limits | `backup_service.py` |
| **Cryptography** | Two-tier PKI hierarchy (Root CA → Intermediate CA → User Certificates), CRL revocation | `pki_manager.py` |
| **Risk Management** | NIST SP 800-30 Rev. 1 Asset Register, Threat-Vuln Matrix, Risk Register, 5×5 Heat Maps | `risk_assessment.py` |
