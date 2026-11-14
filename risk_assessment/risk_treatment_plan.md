# NIST SP 800-30 Risk Treatment Plan
### Secure Document Management and E-Signature System

In accordance with NIST SP 800-30 and ISO/IEC 27005 guidelines, each identified risk is assigned a specific treatment strategy (**Mitigate**, **Transfer**, **Accept**, or **Avoid**), alongside prioritized action plans and estimated implementation costs.

| Risk ID | Identified Risk | Treatment Strategy | Implemented & Planned Controls | Priority | Cost Estimate (Lab / Production) | Responsible Party |
|---|---|---|---|:---:|---|---|
| **RSK-01** | Private Key Theft | **Mitigate** | Offline root key storage on air-gapped encrypted USB; filesystem access restriction (chmod 600); annual key rotation. | **P1 (Highest)** | \$0 (Lab) / \$500 (Production HSM/KMS) | Admin / Security Lead |
| **RSK-02** | Eavesdropping / MITM | **Mitigate** | TLS 1.2/1.3 with custom PKI certificates; HSTS preload; disable insecure ciphers. | **P1** | \$0 (OpenSSL PKI) / \$0 (Let's Encrypt / Lab CA) | DevSecOps Engineer |
| **RSK-03** | Silent Document Tampering | **Mitigate** | SHA-256 integrity hash calculated at upload; RSA digital signatures; download-time re-verification. | **P1** | \$0 (Python `cryptography`) | Backend Developer |
| **RSK-04** | Signature Repudiation | **Mitigate** | Unique RSA keypair issued per staff member; immutable audit logging of signing events. | **P2** | \$0 (OpenSSL Scripts) | Admin |
| **RSK-05** | Credential Cracking | **Mitigate** | Argon2id memory-hard password hashing (64MB RAM cost); TOTP MFA; Nginx login rate limit. | **P1** | \$0 (Argon2 / PyOTP) | Backend Developer |
| **RSK-06** | Rogue / Expired Cert | **Mitigate** | Active Certificate Revocation List (CRL) generation; certificate expiration alerting. | **P2** | \$0 (OpenSSL CRL) | PKI Administrator |
| **RSK-07** | DoS API Flooding | **Mitigate** | Nginx `limit_req` zones (5 req/min login, 60 req/min API); ufw firewall rules. | **P2** | \$0 (OpenSSL / Nginx) | System Administrator |
| **RSK-08** | Privilege Escalation | **Mitigate** | Explicit `@role_required` decorators on all API endpoints; JWT payload role validation. | **P2** | \$0 (Flask RBAC) | Backend Developer |
| **RSK-09** | Storage Crash / Loss | **Mitigate & Transfer** | Automated daily backup via cron (`backup.sh`); monthly timed restore test; offsite copy. | **P1** | \$0 (Lab cron) / \$20/mo (Cloud S3 backup) | System Administrator |
| **RSK-10** | Audit Tampering | **Mitigate** | Dedicated database table with append-only access pattern; restricted CSV export. | **P3** | \$0 (PostgreSQL) | Backend Developer |

---

### Treatment Priority Matrix:
- **P1 (Critical / Immediate)**: Must be active prior to initial system testing (RSK-01, RSK-02, RSK-03, RSK-05, RSK-09).
- **P2 (High / Required)**: Implemented during core feature integration (RSK-04, RSK-06, RSK-07, RSK-08).
- **P3 (Medium / Standard)**: Operational monitoring and audit hardening (RSK-10).
