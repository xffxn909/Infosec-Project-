# Secure Document Management & E-Signature System

> **InfoSec Semester Project** — FAST-NUCES  
> **Course:** Information Security  
> **Branch:** `mohsin` (team member branches merge to `main` via PR)

---

## Overview

The **Secure Document Management & E-Signature System** is a web-based platform that enables organisations to upload, manage, digitally sign, and verify sensitive documents with strong cryptographic guarantees. The system is designed around the **CIA Triad**:

| Property | Implementation |
|---|---|
| **Confidentiality** | Argon2id password hashing, JWT authentication, role-based access control (RBAC), TLS in transit, files stored with hashed filenames |
| **Integrity** | SHA-256 document fingerprinting on upload and re-verified on every download; RSA digital signatures stored and verifiable at any time |
| **Availability** | Dockerised services with health checks, automated daily backups, `ON_FAILURE` restart policy, Railway cloud deployment with RTO of 1 hour |

---

## Team

| Name | CMS ID | Role |
|---|---|---|
| Syed Muhammad Ali Hassan | 549075 | Backend / PKI Lead |
| Mohsin Zia | 561256 | DevOps / Security Architecture |
| Affan Tariq | 551279 | Frontend / API Integration |
| Mian Muhammad Sibghatullah Saeed | 542378 | Database / Risk Assessment |

---

## Architecture

```
                     ┌───────────────────────────────┐
                     │          Client Browser        │
                     └───────────────┬───────────────┘
                                     │ HTTPS (443)
                     ┌───────────────▼───────────────┐
                     │      nginx Reverse Proxy        │
                     │   TLS termination · rate limit  │
                     └────────┬──────────┬────────────┘
                              │          │
               ┌──────────────▼──┐  ┌───▼──────────────┐
               │  React Frontend │  │  Flask REST API   │
               │  (Vite / nginx) │  │  /api/*           │
               └─────────────────┘  └───────┬───────────┘
                                            │
                              ┌─────────────▼──────────┐
                              │  PostgreSQL Database    │
                              │  (Users, Documents,    │
                              │   Signatures, AuditLog)│
                              └────────────────────────┘

PKI Infrastructure (out-of-band)
  pki/root-ca/           ← Root CA (offline)
  pki/intermediate-ca/   ← Intermediate CA (online, server-side)
  backend/keys/          ← Per-user RSA signing keys (600 perms)
```

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| **Backend** | Python 3.11 / Flask | REST API with blueprints |
| **Frontend** | React 18 / Vite | SPA, Axios for API calls |
| **Database** | PostgreSQL 15 | SQLAlchemy ORM + Flask-Migrate |
| **PKI** | OpenSSL 3.x | Root CA → Intermediate CA → User Certs |
| **Cryptography** | RSA-2048 / SHA-256 / Argon2id | Via Python `cryptography` library |
| **MFA** | TOTP (RFC 6238) | `pyotp` + QR code enrolment |
| **Auth** | JWT (Bearer token) | `flask-jwt-extended` |
| **Containerisation** | Docker + Docker Compose | Multi-stage builds |
| **Deployment** | Railway + Docker | `railway.toml` configured |

---

## Security Features

### Confidentiality Controls
- **Argon2id** password hashing (memory-hard, resistant to GPU attacks)
- **JWT** access tokens with short expiry (15 min), refresh token rotation
- **TOTP-based MFA** with QR code enrolment flow
- **RBAC** — three roles: `admin`, `manager`, `staff` enforced at every endpoint
- Files stored with **SHA-256 derived filenames** (original name never exposed in storage path)
- **TLS 1.2+** enforced at nginx layer; HTTP redirected to HTTPS

### Integrity Controls
- **SHA-256 hash** computed at upload time, stored in DB, re-verified on every download
- **RSA-2048 digital signatures** per document per signer
- Signature verification endpoint returns detailed result (hash match + crypto validity)
- **AuditLog** table records every mutating action with IP, timestamp, user, and details (JSON)
- Database foreign key constraints prevent orphaned signatures

### Availability Controls
- Docker **health checks** on all services; `restart: unless-stopped`
- Railway `restartPolicyType = "ON_FAILURE"` for cloud resilience
- **Daily automated backups** at 02:00 (`backup.sh` + cron) — 7-day rolling retention
- **RTO: 1 hour** / **RPO: 24 hours** (documented in `risk_assessment/policies/backup_recovery_policy.md`)
- PostgreSQL named volume for data persistence across container restarts

### Additional Security Measures
- Non-root Docker user (`appuser`) in backend image
- Private keys stored with **mode 600** (`backend/keys/`, `pki/*/private/`)
- Root CA key kept **offline** (USB + locked cabinet)
- CRL-based revocation via `scripts/revoke_cert.sh`
- All key operations logged in AuditLog table

---

## Getting Started (Local Development)

### Prerequisites
- Docker ≥ 24 and Docker Compose ≥ 2.x
- Git
- OpenSSL 3.x (for PKI setup)

### Steps

```bash
# 1. Clone the repository
git clone <repo-url>
cd InfosecProject

# 2. Checkout your working branch (or main)
git checkout mohsin   # or main / your branch

# 3. Create your local environment file
cp backend/.env.example .env
# Edit .env — set POSTGRES_PASSWORD, JWT_SECRET_KEY, SECRET_KEY to strong random values

# 4. Build and start all services
docker-compose up --build -d

# 5. Wait for the backend health check to pass, then run DB migrations
docker-compose exec backend flask db upgrade

# 6. Run PKI setup (creates Root CA, Intermediate CA)
bash pki/setup_pki.sh

# 7. Access the application
#    Frontend:  http://localhost
#    API docs:  http://localhost/api/health
#    Direct FE: http://localhost:3000  (dev port)
```

> **First-time login:** The first `POST /api/auth/register` request creates an admin account.

---

## Zero-Cost Deployment Options (University / Lab)

### Option 1: Docker Compose (100% Free - Recommended for Evaluation)
No cloud services or credit cards required. Evaluators or team members can run the full environment locally or on any lab machine:
```bash
docker compose up --build
```
- Frontend UI: `http://localhost:3000` (or `https://localhost` via Nginx)
- Backend REST API: `http://localhost:5000/api/`

### Option 2: Render.com (100% Free Cloud Tier - No Credit Card)
A `render.yaml` Blueprint is included for zero-cost cloud deployment:
1. Push to your GitHub repo.
2. Sign in to [Render.com](https://render.com) (free account).
3. Go to **Blueprints** → **New Blueprint Instance** → Select repository.
4. Render provisions the PostgreSQL database, Flask backend web service, and React static site automatically at zero cost.

### Option 3: Railway (Optional)
A `railway.toml` configuration is also provided if deploying to a Railway account.

---

See [`pki/README.md`](pki/README.md) for full PKI documentation including:
- Creating the Root CA and Intermediate CA
- Issuing user signing certificates
- Revoking certificates and updating the CRL
- Key storage requirements

---

## Project Structure

```
InfosecProject/
├── .gitignore                      # Excludes private keys, .env, node_modules, etc.
├── Dockerfile                      # Backend multi-stage Docker image
├── docker-compose.yml              # Full stack: db + backend + frontend + nginx
├── railway.toml                    # Railway cloud deployment config
├── README.md                       # This file
│
├── backend/
│   ├── requirements.txt            # Python dependencies
│   ├── .env.example                # Environment variable template
│   ├── run.py                      # Flask app entry point
│   └── app/
│       ├── __init__.py             # App factory
│       ├── config.py               # Config from environment
│       ├── models.py               # SQLAlchemy models
│       ├── auth/                   # Auth blueprint (register, login, MFA)
│       ├── documents/              # Documents blueprint (upload, sign, verify)
│       ├── audit/                  # Audit log blueprint
│       └── admin/                  # Admin blueprint (user management)
│
├── frontend/
│   ├── Dockerfile                  # Frontend multi-stage Docker image
│   ├── package.json
│   └── src/                        # React + Vite source (do not modify here)
│
├── nginx/
│   ├── nginx.conf                  # Main nginx reverse proxy config
│   └── frontend.conf               # Frontend SPA + API proxy config
│
├── pki/
│   ├── README.md                   # PKI documentation
│   ├── root-ca/                    # Root Certificate Authority
│   │   ├── private/                # 🔒 NEVER committed (in .gitignore)
│   │   └── certs/
│   ├── intermediate-ca/            # Intermediate CA
│   │   ├── private/                # 🔒 NEVER committed (in .gitignore)
│   │   └── certs/
│   └── certs/                      # Issued public certificates
│
├── scripts/
│   ├── setup_pki.sh                # PKI bootstrapping script
│   ├── backup.sh                   # Backup and restore script
│   └── revoke_cert.sh              # Certificate revocation script
│
└── risk_assessment/
    ├── README.md                   # Risk assessment overview (NIST SP 800-30)
    ├── risk_register.md            # Identified threats and risk ratings
    ├── threat_model.md             # STRIDE threat model
    └── policies/
        ├── private_key_management_policy.md
        └── backup_recovery_policy.md
```

---

## Git Workflow

Each team member works on a dedicated branch and submits a Pull Request to `main` for review.

| Branch | Owner | Scope |
|---|---|---|
| `main` | All (via PR) | Production-ready, reviewed code only |
| `mohsin` | Mohsin Zia | DevOps, Docker, deployment, project docs |
| `ali` | Syed Muhammad Ali Hassan | Backend API, PKI scripts |
| `affan` | Affan Tariq | Frontend React components |
| `sibghat` | Mian Muhammad Sibghatullah Saeed | Database schema, risk assessment |

**Branch Rules:**
1. Never push directly to `main`
2. PRs require at least one team member review
3. All CI checks (lint, tests) must pass before merge
4. Squash-merge to keep `main` history clean

---

## Module 1 Deliverables

- [x] Project proposal submitted
- [x] Repository created with branch strategy
- [x] CIA triad analysis documented
- [x] Initial system architecture diagram
- [x] Technology stack finalised
- [x] NIST SP 800-30 risk assessment started (`risk_assessment/`)
- [x] STRIDE threat model drafted

---

## Module 2 Deliverables

- [x] PKI infrastructure (Root CA + Intermediate CA) set up
- [x] Flask backend API — all endpoints implemented
- [x] JWT authentication + TOTP MFA
- [x] RBAC enforcement (`admin`, `manager`, `staff`)
- [x] SHA-256 document hashing on upload and download
- [x] RSA-2048 digital signature + verification
- [x] Audit log (all actions recorded with IP, timestamp, user)
- [x] React frontend — login, MFA setup, document management UI
- [x] Docker Compose full-stack deployment
- [x] Railway deployment configured (`railway.toml`)
- [x] Private Key Management Policy written
- [x] Backup & Recovery Policy written (RTO 1h / RPO 24h)
- [ ] Penetration testing report
- [ ] Final presentation

---

## License

This project is developed for academic purposes as part of the Information Security course at FAST-NUCES. All rights reserved by the team members.
