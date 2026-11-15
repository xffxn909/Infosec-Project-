# Secure Document Management & E-Signature System

> **InfoSec Semester Project** — FAST-NUCES  
> **Course:** Information Security  
> **Repository:** `https://github.com/xffxn909/Infosec-Project-`  
> **Branch:** `sibgatullah`

---

## 👥 Team Members & Contributions

| Name | CMS ID | Primary Role |
|---|---|---|
| **Syed Muhammad Ali Hassan** | 549075 | PKI & Standalone Application Prototype |
| **Mohsin Zia** | 561256 | Enterprise Architecture, Backend API & DevOps |
| **Affan Tariq** | 551279 | Frontend Integration, Unification & Bugfixes |
| **Mian Muhammad Sibghatullah Saeed** | 542378 | Integration Lead, Docker & Architecture Standardization |

---

## 📋 Overview

The **Secure Document Management & E-Signature System** is an enterprise-grade platform that enables organisations to securely upload, store, digitally sign, and verify sensitive documents with strong cryptographic guarantees. The platform strictly implements controls according to the **CIA Triad** and **NIST SP 800-30 Rev. 1 Risk Assessment Framework**.

| Property | Implementation |
|---|---|
| **Confidentiality** | **Argon2id** password hashing (memory-hard, resistant to GPU/ASIC attacks), **JWT** authentication, **TOTP MFA** (RFC 6238 / Google Authenticator), Role-Based Access Control (**RBAC**: Admin, Manager, Staff), and TLS 1.2/1.3 reverse proxy termination. |
| **Integrity** | **SHA-256** cryptographic fingerprinting on upload and download, **RSA-2048 / ECDSA** digital signatures with verification reports, and an immutable, structured **AuditLog** recording every system mutation. |
| **Availability** | Automated daily backup archives, timed restore testing demonstrating Recovery Time Objective (**RTO < 1 hour**), and Nginx rate-limiting zones (5 req/min on login, 60 req/min general API) for DoS and brute-force mitigation. |

---

## 🏗️ Architecture

```
                     ┌───────────────────────────────┐
                     │          Client Browser        │
                     └───────────────┬───────────────┘
                                     │ HTTPS (Port 443 / Port 80)
                     ┌───────────────▼───────────────┐
                     │      Nginx Reverse Proxy       │
                     │  TLS termination · Rate limit  │
                     └────────┬──────────┬────────────┘
                              │          │
               ┌──────────────▼──┐  ┌───▼──────────────┐
               │  React Frontend │  │  Flask REST API   │
               │  (Vite / Nginx) │  │  /api/*           │
               └─────────────────┘  └───────┬───────────┘
                                            │
                              ┌─────────────▼──────────┐
                              │  PostgreSQL Database    │
                              │  (Users, Documents,    │
                              │   Signatures, AuditLog)│
                              └────────────────────────┘

PKI Hierarchy (pki/):
  Root CA (4096-bit RSA) ──► Intermediate CA (4096-bit RSA) ──► Server & User Signing Certs + CRL
```

---

## 🚀 Execution & Deployment Options

The project provides two fully functional execution modes to satisfy both production deployment standards and quick local grading:

### Option 1: Full Enterprise Stack (Docker Compose — Recommended)
Run the complete multi-container architecture (PostgreSQL, Flask REST API, React 18 SPA, and Nginx Reverse Proxy with TLS and rate limiting):

```bash
# 1. Clone repository and navigate to root
git clone https://github.com/xffxn909/Infosec-Project-.git
cd Infosec-Project-

# 2. Copy environment file template
cp .env.example .env

# 3. Setup PKI certificates (generates Root CA, Intermediate CA, Server Certs)
bash pki/setup_ca.sh

# 4. Start all containers
docker compose up --build -d

# 5. Access the applications:
#    - Frontend SPA: http://localhost:3000 (or https://localhost via Nginx)
#    - API Health:   http://localhost:5000/api/health
```

### Option 2: Lightweight Standalone Prototype (Single Python Process)
Run the self-contained, single-machine version with SQLite and structured Jinja2 templates (no Docker or PostgreSQL required):

```bash
# 1. Navigate to standalone directory
cd standalone

# 2. Install lightweight dependencies
pip install -r requirements.txt

# 3. Run PKI test, risk assessment, and backup drills
python pki_manager.py
python risk_assessment.py
python backup_service.py

# 4. Start the standalone web server
python app.py
```
Open **http://127.0.0.1:5000** in your browser.  
Default Admin Credentials: `admin` / `Admin@1234`.

---

## 🧪 Security & Verification Scripts

In addition to the web applications, standalone verification scripts are provided under `scripts/`:

```bash
# 1. SHA-256 Tamper Detection Demo
python scripts/hash_verify.py --demo README.md

# 2. Password Hash Cracking Demo (MD5 dictionary crack vs Argon2id resilience)
python scripts/cracking_demo.py

# 3. Automated Backup & Restore Drill
bash scripts/backup.sh --test-restore
```

---

## 📂 Repository Structure

```
Infosec-Project-/
├── .gitignore                      # Excludes private keys, databases, WAL, and pycache
├── .env.example                    # Environment template for Docker Compose
├── Dockerfile                      # Multi-stage Dockerfile for Flask Backend
├── docker-compose.yml              # Multi-container orchestration (db, backend, frontend, nginx)
├── render.yaml                     # Render.com zero-cost cloud deployment blueprint
├── railway.toml                    # Railway deployment configuration
├── README.md                       # Main documentation
│
├── backend/                        # Enterprise REST API (Flask application factory)
│   ├── app/
│   │   ├── __init__.py             # Factory pattern & blueprint registration
│   │   ├── config.py               # Environment configuration
│   │   ├── models.py               # SQLAlchemy ORM models (User, Document, Signature, AuditLog)
│   │   ├── utils.py                # Helpers (circular-import-safe key generator & logger)
│   │   ├── auth/                   # Authentication blueprint (Argon2, JWT, TOTP MFA)
│   │   ├── documents/              # Document management & crypto blueprint
│   │   ├── audit/                  # Audit trail logging blueprint
│   │   └── admin/                  # Administrative operations blueprint
│   ├── requirements.txt            # Backend dependencies
│   └── run.py                      # Application entry point
│
├── frontend/                       # Modern React 18 SPA (Vite + Tailwind CSS)
│   ├── Dockerfile                  # Multi-stage build (Node -> Nginx)
│   ├── package.json
│   └── src/                        # React components, contexts, pages, and API clients
│
├── nginx/                          # Nginx reverse proxy configuration
│   ├── nginx.conf                  # Main config with rate-limiting zones
│   ├── frontend.conf               # SPA serving configuration for frontend container
│   └── securedocs.conf             # TLS termination, security headers, and API proxy
│
├── pki/                            # OpenSSL PKI Infrastructure
│   ├── setup_ca.sh                 # Generates Root CA, Intermediate CA, and Server Certs
│   ├── issue_user_cert.sh          # Issues user signing certificates
│   ├── revoke_cert.sh              # Revokes certificates and updates CRL
│   ├── certs/                      # Public certificates & chains
│   └── crl/                        # Certificate Revocation Lists
│
├── scripts/                        # Demonstration & testing scripts
│   ├── backup.sh                   # Daily backup & restore SLA verification
│   ├── cracking_demo.py            # MD5 vs Argon2 cracking benchmark
│   └── hash_verify.py              # SHA-256 fingerprinting & tamper detection
│
├── standalone/                     # Lightweight Single-Process Prototype
│   ├── app.py                      # Clean Flask server with Jinja2 rendering
│   ├── auth.py                     # Authentication & TOTP MFA
│   ├── database.py                 # SQLite data layer
│   ├── document_service.py         # Upload & digital signing service
│   ├── backup_service.py           # Backup & restore drills
│   ├── pki_manager.py              # Pure Python PKI & cryptography
│   ├── risk_assessment.py          # NIST SP 800-30 calculations & report generator
│   ├── create_user.py              # CLI user creation tool
│   ├── templates/                  # Modular Jinja2 HTML templates
│   └── README.md                   # Standalone guide
│
└── risk_assessment/                # NIST SP 800-30 Rev. 1 Risk Documentation
    ├── asset_register.md           # CIA-valued asset inventory
    ├── threat_vulnerability_matrix.md # Threat vectors & vulnerability mappings
    ├── risk_register.md            # Pre- and post-control risk scores & 5x5 heatmap
    ├── risk_treatment_plan.md      # Treatment prioritization & deadlines
    └── policies/                   # Security governance policies
```

---

## 🔒 Security Compliance Summary

- **NIST SP 800-30 Rev. 1:** Comprehensive risk analysis covering all assets, threats, and mitigations.
- **Zero Committed Secrets:** No private keys (`.key`), SQLite databases (`.db`), or credentials are tracked in version control.
- **Defence-in-Depth:** Rate limiting at proxy layer, role-based checks at API layer, cryptographic integrity checks at storage layer.
