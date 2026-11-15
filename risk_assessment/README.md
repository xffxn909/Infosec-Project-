# Risk Assessment — Secure Document Management & E-Signature System

## Purpose

This directory contains the formal risk assessment artefacts for the **Secure Document Management & E-Signature System**. The assessment follows the **NIST Special Publication 800-30 Rev. 1** framework: *Guide for Conducting Risk Assessments*.

---

## Framework: NIST SP 800-30 Rev. 1

NIST SP 800-30 provides a structured, repeatable process for identifying, estimating, and responding to information security risks. The process consists of four steps:

| Step | Activity |
|---|---|
| **1. Prepare** | Identify purpose, scope, assumptions, constraints, and information sources |
| **2. Conduct** | Identify threat sources and events, determine likelihood and impact, calculate risk |
| **3. Communicate** | Share findings with decision makers and stakeholders |
| **4. Maintain** | Monitor risk factors and update the assessment periodically |

Risk ratings in this assessment use a **3×3 qualitative matrix**:

| | **Low Impact** | **Medium Impact** | **High Impact** |
|---|---|---|---|
| **High Likelihood** | Medium | High | Critical |
| **Medium Likelihood** | Low | Medium | High |
| **Low Likelihood** | Low | Low | Medium |

---

## Files in This Directory

| File | Description |
|---|---|
| `README.md` | This document — framework overview and file guide |
| `risk_register.md` | Complete risk register: threat sources, events, likelihood, impact, current controls, residual risk, and treatment plan |
| `threat_model.md` | STRIDE-based threat model mapping threats to system components |
| `policies/private_key_management_policy.md` | Formal policy governing RSA key generation, storage, rotation, revocation, and incident response |
| `policies/backup_recovery_policy.md` | Formal policy governing backup schedules, retention, restore procedures, and RTO/RPO commitments |

---

## Scope

The assessment covers all components of the system:

- **Backend Flask API** — authentication, document handling, signing, audit
- **Frontend React SPA** — user interface and API integration
- **PostgreSQL Database** — user, document, signature, and audit data
- **PKI Infrastructure** — Root CA, Intermediate CA, user signing certificates
- **nginx Reverse Proxy** — TLS termination, request routing
- **Docker deployment environment** — container runtime and orchestration
- **Railway cloud platform** — hosting environment

**Out of scope:** End-user devices, corporate network infrastructure, ISP-level threats.

---

## Assumptions & Constraints

1. The system is deployed on Railway's cloud infrastructure; physical security of servers is Railway's responsibility.
2. The Root CA private key is stored offline (USB drive in a locked cabinet) — physical security of the storage medium is assumed adequate.
3. Team members follow the access control and key management policies defined in this directory.
4. The system will be used by a small organisation (< 100 users) during the academic demonstration phase.

---

## Risk Treatment Strategy

| Risk Level | Treatment |
|---|---|
| **Critical** | Must be mitigated before go-live; compensating controls mandatory |
| **High** | Mitigate with priority; document residual risk and accept if impractical to fully remediate |
| **Medium** | Apply cost-effective controls; monitor and review quarterly |
| **Low** | Accept; document and monitor annually |

---

## Review Schedule

This risk assessment is reviewed:
- **Annually** as part of the policy review cycle
- **After any significant system change** (new feature, infrastructure change, security incident)
- **After any security incident** involving data loss, unauthorised access, or key compromise

---

## References

- NIST SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
- NIST SP 800-53 Rev. 5 — Security and Privacy Controls
- OWASP Top 10 (2021)
- STRIDE Threat Modelling Methodology (Microsoft)
