# NIST SP 800-30 Risk Register & 5×5 Heat Map
### Secure Document Management and E-Signature System

Scoring Methodology (1 to 5 Scale):
- **Likelihood (L)**: 1 (Rare), 2 (Unlikely), 3 (Moderate), 4 (Likely), 5 (Almost Certain)
- **Impact (I)**: 1 (Insignificant), 2 (Minor), 3 (Moderate), 4 (Major), 5 (Catastrophic)
- **Risk Score (R)**: $R = L \times I$
  - **Low (1–4)** | **Medium (5–9)** | **High (10–14)** | **Critical (15–25)**

---

## 5×5 Risk Matrix / Heat Map

### Pre-Control Risk Distribution (Before Module 1)
```
Impact  →    1 (Insignif)   2 (Minor)     3 (Mod)       4 (Major)       5 (Catastrophic)
Likelihood ↓
5 (Almost Certain)  -             -             -             THR-05 (20)     -
4 (Likely)          -             -             THR-07 (12)   THR-02 (16)     THR-01 (20)
3 (Moderate)        -             -             THR-08 (9)    THR-03 (12)     THR-09 (15)
2 (Unlikely)        -             -             THR-10 (6)    THR-04 (8)      THR-06 (10)
1 (Rare)            -             -             -             -               -
```

### Post-Control Residual Risk Distribution (After Module 1)
```
Impact  →    1 (Insignif)   2 (Minor)     3 (Mod)       4 (Major)       5 (Catastrophic)
Likelihood ↓
5 (Almost Certain)  -             -             -             -               -
4 (Likely)          -             -             -             -               -
3 (Moderate)        -             -             -             -               -
2 (Unlikely)        -             THR-07 (4)    THR-08 (6)    THR-05 (8)      -
1 (Rare)            -             THR-10 (2)    THR-06 (3)    THR-03 (4), 04  THR-01 (5), 02, 09
```

---

## Comprehensive Risk Register Table

| Risk ID | Threat Scenario | Pre-Control L | Pre-Control I | Pre-Control Score | Implemented Module 1 Security Controls | Post-Control L | Post-Control I | Residual Score | Risk Level |
|---|---|:---:|:---:|:---:|---|:---:|:---:|:---:|:---:|
| **RSK-01** | Private Key Theft | 4 | 5 | **20 (Critical)** | Offline Root CA key, strict 600 file permissions, RSA-4096 Intermediate CA, Private Key Policy | 1 | 5 | **5** | Low |
| **RSK-02** | Eavesdropping / MITM | 4 | 4 | **16 (Critical)** | Full TLS 1.2/1.3 termination, custom CA-issued certificates, HSTS enabled, HTTP to HTTPS redirect | 1 | 4 | **4** | Low |
| **RSK-03** | Silent Document Tampering | 3 | 4 | **12 (High)** | SHA-256 hash computed at upload; RSA digital signatures; verification script `hash_verify.py` flags tamper | 1 | 4 | **4** | Low |
| **RSK-04** | Signature Repudiation | 2 | 4 | **8 (Medium)** | Individual RSA signing key per staff member; cryptographic timestamping and signature database linkage | 1 | 4 | **4** | Low |
| **RSK-05** | Credential Cracking | 5 | 4 | **20 (Critical)** | Argon2id slow, memory-hard hashing with 16-byte salt; Nginx login rate limit (5 req/min); TOTP MFA | 2 | 4 | **8** | Medium |
| **RSK-06** | Revoked / Expired Cert | 2 | 5 | **10 (High)** | Certificate Revocation List (CRL) infrastructure via OpenSSL `pki/revoke_cert.sh` script | 1 | 3 | **3** | Low |
| **RSK-07** | DoS API Flooding | 4 | 3 | **12 (High)** | Nginx reverse proxy rate limiting zones (`limit_req_zone`: 60 req/min general, 5 req/min auth) | 2 | 2 | **4** | Low |
| **RSK-08** | Unauthorized Access | 3 | 3 | **9 (Medium)** | Role-Based Access Control (Admin, Manager, Staff) decorators on all backend routes | 2 | 3 | **6** | Medium |
| **RSK-09** | Storage Crash / Loss | 3 | 5 | **15 (Critical)** | Daily automated `backup.sh` with PostgreSQL dump + uploads archive; automated timed restore test | 1 | 5 | **5** | Low |
| **RSK-10** | Audit Tampering | 2 | 3 | **6 (Medium)** | Dedicated `AuditLog` table with IP logging, timestamping; read-only access for staff | 1 | 2 | **2** | Low |

---

## Conclusion & Residual Risk Assessment
With the implementation of the Module 1 CIA controls and cryptographic mechanisms, **all critical risks have been treated and reduced to acceptable residual levels (scores $\le 8$)**.
