"""
risk_assessment.py
==================
Module 2 – Risk Assessment (NIST SP 800-30)
  - Asset Register
  - Threat & Vulnerability Matrix
  - 5×5 Risk Heat Map (likelihood × impact)
  - Risk Register with before/after control scoring
  - Risk Treatment Plan
  - Policy stubs: Private Key Management + Backup & Recovery
"""

import json
import datetime
from pathlib import Path

REPORT_DIR = Path("risk_reports")
REPORT_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Asset Register
# ─────────────────────────────────────────────────────────────────────────────

ASSET_REGISTER = [
    {"id": "A1", "name": "Web Application Server",    "type": "Server",      "value": "High"},
    {"id": "A2", "name": "Document Database (SQLite)", "type": "Data",        "value": "High"},
    {"id": "A3", "name": "Uploaded Documents",         "type": "Data",        "value": "Critical"},
    {"id": "A4", "name": "Root CA Private Key",        "type": "Key",         "value": "Critical"},
    {"id": "A5", "name": "Intermediate CA Key",        "type": "Key",         "value": "High"},
    {"id": "A6", "name": "User Signing Keys",          "type": "Key",         "value": "High"},
    {"id": "A7", "name": "Staff Accounts",             "type": "Account",     "value": "Medium"},
    {"id": "A8", "name": "TLS Certificates",           "type": "Certificate", "value": "High"},
    {"id": "A9", "name": "Backup Archives",            "type": "Data",        "value": "High"},
    {"id": "A10","name": "Office Network",             "type": "Network",     "value": "Medium"},
    {"id": "A11","name": "System Administrators",      "type": "People",      "value": "High"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Threat & Vulnerability Matrix
# ─────────────────────────────────────────────────────────────────────────────

THREAT_MATRIX = [
    {
        "id": "T1",
        "threat": "Private Key Theft",
        "assets": ["A4", "A5", "A6"],
        "vulnerability": "Keys stored unencrypted on disk; no HSM",
        "attack_vector": "Insider threat / malware",
    },
    {
        "id": "T2",
        "threat": "Expired / Revoked Certificate Not Checked",
        "assets": ["A8"],
        "vulnerability": "CRL not checked on every connection; OCSP not deployed",
        "attack_vector": "Man-in-the-middle with expired cert",
    },
    {
        "id": "T3",
        "threat": "Weak Password / Brute Force",
        "assets": ["A7"],
        "vulnerability": "Staff choose weak passwords; no lockout policy",
        "attack_vector": "Online brute force / credential stuffing",
    },
    {
        "id": "T4",
        "threat": "Document Tampering",
        "assets": ["A3", "A2"],
        "vulnerability": "No integrity check on documents at rest",
        "attack_vector": "Insider modifies file directly on disk",
    },
    {
        "id": "T5",
        "threat": "Denial of Service (DoS)",
        "assets": ["A1", "A10"],
        "vulnerability": "No rate limiting; no firewall rules",
        "attack_vector": "HTTP flood / SYN flood from office network",
    },
    {
        "id": "T6",
        "threat": "Data Loss (Ransomware / Disk Failure)",
        "assets": ["A2", "A3", "A9"],
        "vulnerability": "No offsite backup; backups stored on same server",
        "attack_vector": "Ransomware encrypts server disk",
    },
    {
        "id": "T7",
        "threat": "Fake / Forged Certificate",
        "assets": ["A8"],
        "vulnerability": "No certificate pinning; Root CA not strictly protected",
        "attack_vector": "Attacker creates rogue cert from compromised CA",
    },
    {
        "id": "T8",
        "threat": "Weak Hash Algorithm (MD5)",
        "assets": ["A7"],
        "vulnerability": "Password stored with MD5 (legacy path)",
        "attack_vector": "Rainbow-table / GPU cracking attack",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Risk Register  (Likelihood × Impact  1-5 scale; score = L × I)
# ─────────────────────────────────────────────────────────────────────────────

RISK_REGISTER = [
    # id, threat_id, likelihood_before, impact, likelihood_after, control_applied
    {"id": "R1", "threat_id": "T1", "L_before": 3, "impact": 5, "L_after": 1, "control": "Keys encrypted at rest; root key kept offline; rotation policy"},
    {"id": "R2", "threat_id": "T2", "L_before": 4, "impact": 4, "L_after": 2, "control": "CRL checked on every signature verification; OCSP stub added"},
    {"id": "R3", "threat_id": "T3", "L_before": 4, "impact": 3, "L_after": 1, "control": "Argon2 hashing; MFA (TOTP); 5-attempt rate limit per 5 min"},
    {"id": "R4", "threat_id": "T4", "L_before": 3, "impact": 5, "L_after": 1, "control": "SHA-256 on upload; ECDSA signing; audit log of all file accesses"},
    {"id": "R5", "threat_id": "T5", "L_before": 3, "impact": 4, "L_after": 2, "control": "In-app rate limiter; Windows firewall rules; Flask connection limits"},
    {"id": "R6", "threat_id": "T6", "L_before": 2, "impact": 5, "L_after": 1, "control": "Daily automated backup; timed restore test; backup integrity check"},
    {"id": "R7", "threat_id": "T7", "L_before": 2, "impact": 5, "L_after": 1, "control": "Root CA strictly protected; certificate chain validation enforced"},
    {"id": "R8", "threat_id": "T8", "L_before": 4, "impact": 4, "L_after": 1, "control": "Argon2 replaces MD5; migration script hashes legacy passwords"},
]


def compute_scores(register: list[dict]) -> list[dict]:
    for r in register:
        r["score_before"] = r["L_before"] * r["impact"]
        r["score_after"] = r["L_after"] * r["impact"]
        r["reduction"] = r["score_before"] - r["score_after"]
        r["rating_before"] = _risk_rating(r["score_before"])
        r["rating_after"] = _risk_rating(r["score_after"])
    return register


def _risk_rating(score: int) -> str:
    if score >= 20:
        return "CRITICAL"
    if score >= 12:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# 5×5 Heat Map (ASCII)
# ─────────────────────────────────────────────────────────────────────────────

def print_heat_map(register: list[dict], phase: str = "before"):
    """Print a 5×5 risk heat map to stdout."""
    field = f"L_{phase}"
    grid = [[[] for _ in range(5)] for _ in range(5)]
    for r in register:
        threat = next(t for t in THREAT_MATRIX if t["id"] == r["threat_id"])
        l = r[field] - 1          # 0-based row
        i = r["impact"] - 1       # 0-based col
        grid[4 - l][i].append(r["id"])

    print(f"\n  5×5 Risk Heat Map ({phase.upper()})")
    print("  Impact →")
    print("  " + "   ".join(["Low", "Med", " H ", "V-H", "Cri"]))
    for row_idx, row in enumerate(grid):
        likelihood = 5 - row_idx
        cells = [",".join(c) if c else " · " for c in row]
        label = f"L={likelihood}"
        print(f"{label}  " + "   ".join(f"{c:^5}" for c in cells))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Risk Treatment Plan
# ─────────────────────────────────────────────────────────────────────────────

TREATMENT_PLAN = [
    {"risk": "R1", "treatment": "Mitigate", "priority": 1, "cost_est": "Low",    "owner": "admin",   "deadline": "Phase 1"},
    {"risk": "R4", "treatment": "Mitigate", "priority": 1, "cost_est": "Low",    "owner": "admin",   "deadline": "Phase 1"},
    {"risk": "R7", "treatment": "Mitigate", "priority": 2, "cost_est": "Low",    "owner": "admin",   "deadline": "Phase 1"},
    {"risk": "R3", "treatment": "Mitigate", "priority": 2, "cost_est": "Low",    "owner": "dev",     "deadline": "Phase 1"},
    {"risk": "R2", "treatment": "Mitigate", "priority": 3, "cost_est": "Medium", "owner": "admin",   "deadline": "Phase 2"},
    {"risk": "R5", "treatment": "Mitigate", "priority": 3, "cost_est": "Medium", "owner": "admin",   "deadline": "Phase 2"},
    {"risk": "R6", "treatment": "Mitigate", "priority": 4, "cost_est": "Medium", "owner": "admin",   "deadline": "Phase 1"},
    {"risk": "R8", "treatment": "Mitigate", "priority": 5, "cost_est": "Low",    "owner": "dev",     "deadline": "Phase 1"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Policies
# ─────────────────────────────────────────────────────────────────────────────

PRIVATE_KEY_POLICY = """
╔══════════════════════════════════════════════════════════════╗
║          PRIVATE KEY MANAGEMENT POLICY  v1.0                 ║
╚══════════════════════════════════════════════════════════════╝

1. PURPOSE
   Ensure private keys used by the Secure Document System are
   generated, stored, used, and destroyed securely.

2. SCOPE
   Root CA key, Intermediate CA key, all user signing keys.

3. KEY GENERATION
   • All keys generated using cryptography library (≥41.0).
   • Root CA: RSA-4096. Intermediate CA: RSA-2048. Users: EC P-256.
   • Generated on an air-gapped machine where possible.

4. KEY STORAGE
   • Root CA key MUST be stored offline (encrypted USB + safe).
   • Intermediate CA key: encrypted at rest (AES-256-GCM).
   • User signing keys: PKCS8 PEM, passphrase-protected.
   • No keys stored in version control or plain-text config files.

5. KEY ACCESS
   • Root CA key: accessed only for Intermediate CA signing (rare).
   • Access logged in audit_log table with actor, timestamp, purpose.
   • Minimum two-person rule for Root CA operations.

6. KEY ROTATION
   • User signing keys: rotated every 90 days.
   • Intermediate CA: rotated every 2 years.
   • Old keys archived (not deleted) for 1 year for verification.

7. KEY REVOCATION
   • Compromised or expired keys revoked via CRL / OCSP within 24 h.
   • Revocation event logged and affected users notified.

8. ENFORCEMENT
   Violations reported to the system administrator. Accounts suspended
   pending investigation.
"""

BACKUP_RECOVERY_POLICY = """
╔══════════════════════════════════════════════════════════════╗
║          BACKUP AND RECOVERY POLICY  v1.0                    ║
╚══════════════════════════════════════════════════════════════╝

1. PURPOSE
   Ensure data can be restored within SLA after any failure.

2. SCOPE
   SQLite database, uploaded documents, PKI files.

3. BACKUP SCHEDULE
   • Full backup: daily at 02:00 (automated via backup_service.py).
   • Backup stored locally in /backups/ AND on a separate NAS/USB.
   • Retention: 30 daily, 12 monthly, 3 yearly copies.

4. BACKUP INTEGRITY
   • Each archive is SHA-256 hashed and hash stored separately.
   • Integrity verified before restore.

5. RESTORE PROCEDURE
   a. Identify latest clean backup.
   b. Run: python backup_service.py --restore <archive>
   c. Verify restored data against hash.
   d. Resume service; notify users.

6. SLA TARGETS
   • Maximum downtime during working hours: 2 hours.
   • Maximum restore time: 1 hour (tested quarterly).

7. TESTING
   • Monthly timed restore drill; results recorded in audit log.
   • Any restore exceeding SLA triggers an incident report.

8. OFFSITE COPIES
   • At least one backup copy kept offsite or in encrypted cloud.
   • Encryption key managed per Private Key Management Policy.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_report():
    scored = compute_scores(RISK_REGISTER)

    lines = []
    lines.append("=" * 70)
    lines.append("   INFORMATION SECURITY RISK ASSESSMENT REPORT")
    lines.append("   Secure Document Management and E-Signature System")
    lines.append(f"   Generated: {datetime.datetime.now().isoformat()}")
    lines.append("   Framework: NIST SP 800-30")
    lines.append("=" * 70)

    lines.append("\n── ASSET REGISTER ──────────────────────────────────────────────────")
    for a in ASSET_REGISTER:
        lines.append(f"  {a['id']:4}  {a['name']:<40} [{a['type']:11}]  Value: {a['value']}")

    lines.append("\n── THREAT & VULNERABILITY MATRIX ───────────────────────────────────")
    for t in THREAT_MATRIX:
        lines.append(f"  {t['id']}  {t['threat']}")
        lines.append(f"       Vuln : {t['vulnerability']}")
        lines.append(f"       Vector: {t['attack_vector']}")

    lines.append("\n── RISK REGISTER ────────────────────────────────────────────────────")
    lines.append(f"  {'ID':4} {'Threat':5} {'L×I Before':11} {'Rating':8} {'L×I After':10} {'Rating'}")
    lines.append("  " + "-" * 60)
    for r in scored:
        lines.append(
            f"  {r['id']:4} {r['threat_id']:5}  "
            f"{r['score_before']:>4}  {r['rating_before']:8}  "
            f"{r['score_after']:>5}  {r['rating_after']}"
        )
        lines.append(f"       Control: {r['control']}")

    lines.append("\n── RISK TREATMENT PLAN ──────────────────────────────────────────────")
    lines.append(f"  {'Risk':5} {'Treatment':10} {'Priority':8} {'Cost':7} {'Owner':8} {'Phase'}")
    lines.append("  " + "-" * 55)
    for t in sorted(TREATMENT_PLAN, key=lambda x: x["priority"]):
        lines.append(
            f"  {t['risk']:5} {t['treatment']:10} {t['priority']:8} "
            f"{t['cost_est']:7} {t['owner']:8} {t['deadline']}"
        )

    report_text = "\n".join(lines)

    report_path = REPORT_DIR / f"risk_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_path.write_text(report_text, encoding="utf-8")

    policy_path = REPORT_DIR / "policies.txt"
    policy_path.write_text(PRIVATE_KEY_POLICY + "\n\n" + BACKUP_RECOVERY_POLICY, encoding="utf-8")

    print(report_text)
    print_heat_map(scored, "before")
    print_heat_map(scored, "after")
    print(f"\n[Risk] Report saved → {report_path}")
    print(f"[Risk] Policies saved → {policy_path}")
    return report_path


if __name__ == "__main__":
    generate_report()
