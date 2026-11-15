# NIST SP 800-30 Asset Register
### Secure Document Management and E-Signature System

The following inventory identifies all hardware, software, data, personnel, and cryptographic assets in scope, categorized by their CIA (Confidentiality, Integrity, Availability) value ratings (**Low**, **Moderate**, **High**).

| Asset ID | Asset Name | Category | Description / Custodian | Confidentiality | Integrity | Availability | Overall Sensitivity |
|---|---|---|---|---|---|---|---|
| **AST-01** | Root CA Private Key | Cryptographic | RSA-4096 offline key; signs intermediate CA | **High** | **High** | **Moderate** | **Critical** |
| **AST-02** | Intermediate CA Private Key | Cryptographic | RSA-4096 key; issues server & user signing certs | **High** | **High** | **High** | **Critical** |
| **AST-03** | User Signing Private Keys | Cryptographic | RSA-2048 keys assigned to staff for e-signatures | **High** | **High** | **Moderate** | **High** |
| **AST-04** | User Credential Store | Data | Argon2id password hashes & TOTP MFA secrets | **High** | **High** | **High** | **Critical** |
| **AST-05** | Document Repository | Data | Uploaded dummy contracts, approvals, letters | **Moderate** | **High** | **High** | **High** |
| **AST-06** | Document SHA-256 Checksums | Data | Cryptographic digests recorded at upload time | **Low** | **High** | **High** | **High** |
| **AST-07** | Digital Signatures Store | Data | Base64-encoded RSA signatures with timestamps | **Low** | **High** | **High** | **High** |
| **AST-08** | Audit Trail & Event Logs | Data | Immutable log of uploads, views, and signs | **Moderate** | **High** | **Moderate** | **High** |
| **AST-09** | PostgreSQL Database Server | Software / DB | Relational store for users, metadata, and logs | **High** | **High** | **High** | **Critical** |
| **AST-10** | Flask Backend API Service | Software / Web | REST API enforcing RBAC, crypto verification | **High** | **High** | **High** | **High** |
| **AST-11** | Nginx Reverse Proxy & TLS | Software / Net | Handles TLS 1.2/1.3 termination, rate limiting | **High** | **High** | **High** | **High** |
| **AST-12** | React Frontend SPA | Software / Web | Client UI for upload, verification, and signing | **Moderate** | **Moderate** | **Moderate** | **Moderate** |
| **AST-13** | Automated Backup Archives | Storage / Data | Daily .sql.gz and uploads.tar.gz archives | **High** | **High** | **High** | **High** |
| **AST-14** | System Administrator | Personnel | Account holding admin role and CA master access | **High** | **High** | **High** | **Critical** |
| **AST-15** | Department Staff / Signers | Personnel | Authorized users initiating and signing files | **Moderate** | **High** | **Moderate** | **Moderate** |

### CIA Valuation Criteria:
- **Confidentiality**: Unauthorized disclosure causes grave damage to organization/staff privacy.
- **Integrity**: Modification or tampering leads to legal non-repudiation failure or fraudulent approvals.
- **Availability**: Downtime disrupts operational workflow; proposal requires RTO < 1 hour, max downtime < 2 hours.
