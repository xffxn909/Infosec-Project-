# Backup and Recovery Policy

**Document ID:** SEC-POL-002  
**Version:** 1.0  
**Effective Date:** November 2026  
**Next Review Date:** November 2027  
**Classification:** Internal — Restricted  

---

## 1. Purpose and Scope

### 1.1 Purpose

This policy establishes the requirements for regular backup of system data, secure storage of backup archives, and timely recovery of the **Secure Document Management & E-Signature System** following a failure or disaster. The policy ensures that **Availability** (the "A" in the CIA Triad) is maintained within defined Recovery Time Objective (RTO) and Recovery Point Objective (RPO) targets.

### 1.2 Scope

This policy covers:

- **PostgreSQL database** — all user, document, signature, and audit log data
- **Document files** — `backend/uploads/` (uploaded document files, stored with hashed filenames)
- **PKI public certificates** — `pki/certs/` (issued certificates and CRL files)

**Explicitly excluded from automated backup** (covered by separate offline procedure):
- Root CA private key (offline USB — not on server)
- Intermediate CA private key (backed up manually per the Private Key Management Policy)

### 1.3 Policy Owner

**Policy Owner:** Security Administrator (Admin role)  
**Operational Responsibility:** Mohsin Zia (DevOps Lead)  
**Backup Verification:** Admin role (any team member with admin access)

---

## 2. Recovery Objectives

| Objective | Target | Rationale |
|---|---|---|
| **Recovery Time Objective (RTO)** | **1 hour** | System must be restored within 1 hour of a declared failure (aligns with project proposal requirement) |
| **Recovery Point Objective (RPO)** | **24 hours** | Maximum acceptable data loss; daily backups ensure no more than one day of data is at risk |

---

## 3. Backup Schedule

### 3.1 Automated Daily Backup

| Parameter | Value |
|---|---|
| **Frequency** | Daily |
| **Time** | 02:00 UTC (low-traffic period) |
| **Mechanism** | `scripts/backup.sh` executed via system cron |
| **Retention** | 7 days rolling (8th oldest backup deleted automatically) |

### 3.2 Cron Configuration

Add the following entry to the server's crontab (`crontab -e` as the deployment user):

```cron
# Secure Document Management System — daily backup at 02:00 UTC
0 2 * * * /bin/bash /app/scripts/backup.sh >> /var/log/securedocs_backup.log 2>&1
```

### 3.3 Backup Contents

Each backup archive contains:

| Component | Source Path | Backup Method |
|---|---|---|
| PostgreSQL database | `DATABASE_URL` (env var) | `pg_dump` → compressed SQL dump |
| Document files | `backend/uploads/` | `tar` archive |
| PKI public certificates | `pki/certs/` | `tar` archive (private keys excluded) |

---

## 4. Backup Storage

### 4.1 Local Storage

Backup archives are stored in a dedicated directory on the server:

```
/backups/securedocs/
  YYYY-MM-DD/
    db_YYYY-MM-DD.sql.gz
    uploads_YYYY-MM-DD.tar.gz
    pki_certs_YYYY-MM-DD.tar.gz
    checksums_YYYY-MM-DD.sha256
```

A SHA-256 checksum file is generated for each archive to verify integrity before and after any restore.

### 4.2 Offsite Copy (Recommended)

For production deployments, offsite copies should be maintained:

- **Railway Volume Snapshots** — enable automatic volume snapshots in the Railway dashboard (daily, 7-day retention)
- **Cloud Storage (Optional)** — `aws s3 sync` or `rclone` to an S3-compatible bucket with server-side encryption (AES-256)

### 4.3 Backup Encryption

Backup archives **should** be encrypted before offsite transmission or storage using GPG:

```bash
# Encrypt a backup archive
gpg --symmetric --cipher-algo AES256 --batch --passphrase-file /etc/securedocs/backup.passphrase \
    db_2026-11-14.sql.gz

# Produces: db_2026-11-14.sql.gz.gpg

# Decrypt for restore
gpg --decrypt --batch --passphrase-file /etc/securedocs/backup.passphrase \
    db_2026-11-14.sql.gz.gpg > db_2026-11-14.sql.gz
```

The backup passphrase must be:
- Minimum 32 characters, randomly generated
- Stored separately from the backup files (password manager or offline document)
- Known to at least two team members (escrow)

---

## 5. Backup Procedure

The `scripts/backup.sh` script performs the following steps automatically:

```bash
#!/usr/bin/env bash
# Simplified backup.sh logic (see scripts/backup.sh for full implementation)

DATE=$(date +%Y-%m-%d)
BACKUP_DIR="/backups/securedocs/${DATE}"
mkdir -p "${BACKUP_DIR}"

# 1. PostgreSQL dump
pg_dump "${DATABASE_URL}" | gzip > "${BACKUP_DIR}/db_${DATE}.sql.gz"

# 2. Document files archive
tar -czf "${BACKUP_DIR}/uploads_${DATE}.tar.gz" -C /app backend/uploads/

# 3. PKI public certificates archive
tar -czf "${BACKUP_DIR}/pki_certs_${DATE}.tar.gz" -C /app pki/certs/

# 4. Generate checksums
sha256sum "${BACKUP_DIR}"/*.gz > "${BACKUP_DIR}/checksums_${DATE}.sha256"

# 5. Remove backups older than 7 days
find /backups/securedocs -maxdepth 1 -type d -mtime +7 -exec rm -rf {} \;

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Backup completed: ${BACKUP_DIR}"
```

---

## 6. Restore Procedure

### 6.1 Pre-Restore Checklist

Before restoring, complete the following:

- [ ] Identify the target backup date (most recent unless specific recovery point is needed)
- [ ] Verify backup archive integrity with checksums: `sha256sum -c checksums_YYYY-MM-DD.sha256`
- [ ] Stop the backend and frontend services to prevent data writes during restore
- [ ] Notify team members that the system is in maintenance mode

### 6.2 Restore Steps

```bash
# 1. Stop services
docker-compose stop backend frontend

# 2. Set target date
DATE="2026-11-14"   # Replace with target backup date
BACKUP_DIR="/backups/securedocs/${DATE}"

# 3. Verify checksums
cd "${BACKUP_DIR}" && sha256sum -c "checksums_${DATE}.sha256"

# 4. Restore PostgreSQL database
#    WARNING: This drops and recreates the database — data loss if wrong date selected
docker-compose exec db psql -U "${POSTGRES_USER}" -c "DROP DATABASE IF EXISTS securedocs;"
docker-compose exec db psql -U "${POSTGRES_USER}" -c "CREATE DATABASE securedocs;"
gunzip -c "${BACKUP_DIR}/db_${DATE}.sql.gz" | \
    docker-compose exec -T db psql -U "${POSTGRES_USER}" -d securedocs

# 5. Restore document uploads
tar -xzf "${BACKUP_DIR}/uploads_${DATE}.tar.gz" -C /app

# 6. Restore PKI certificates (if needed)
tar -xzf "${BACKUP_DIR}/pki_certs_${DATE}.tar.gz" -C /app

# 7. Restart services
docker-compose start backend frontend

# 8. Verify system health
curl -s http://localhost/api/health | python3 -m json.tool
```

### 6.3 Using the Restore Script

The backup script supports a `--restore` flag for convenience:

```bash
bash scripts/backup.sh --restore 2026-11-14
```

This automates steps 3–8 above with interactive confirmation prompts.

### 6.4 Post-Restore Verification

After restore, verify:

1. **API health:** `GET /api/health` returns `{"status": "ok"}`
2. **Login works:** Admin user can authenticate
3. **Documents accessible:** At least one document upload/download cycle completes successfully
4. **Audit log intact:** `GET /api/audit` returns expected entries
5. **Record restore event:** Log the restore in a maintenance log (date, operator, backup date used, reason)

---

## 7. Restore Testing

### 7.1 Monthly Restore Test

A timed restore test is conducted **monthly** to verify that:
- Backup archives are valid and not corrupted
- The restore procedure can be completed within the **1-hour RTO**
- Team members are familiar with the restore procedure

### 7.2 Test Procedure

1. Provision a test environment (Docker Compose on a local machine)
2. Copy the latest backup archives to the test environment
3. Execute `bash scripts/backup.sh --restore <date>` on test environment
4. Verify system health (Section 6.4)
5. Record elapsed time; confirm it is under 60 minutes
6. Document result in the monthly restore test log

### 7.3 Test Log Template

| Date | Operator | Backup Date Used | Elapsed Time | RTO Met? | Issues |
|---|---|---|---|---|---|
| 2026-11-14 | Mohsin Zia | 2026-11-13 | 35 min | ✅ Yes | None |

---

## 8. Responsibilities

| Role | Responsibility |
|---|---|
| **Security Administrator (Admin)** | Owns this policy; authorises restore operations; reviews monthly test results |
| **DevOps Lead (Mohsin Zia)** | Maintains `backup.sh` script; configures cron; monitors backup logs |
| **All team members** | Must not delete or modify backup archives; must report backup failures immediately |

---

## 9. Monitoring and Alerting

- Backup script logs to `/var/log/securedocs_backup.log`
- A non-zero exit code from `backup.sh` indicates failure — cron will log this to system mail
- **Recommended:** Set up a cron-based log check that alerts if the most recent backup file is older than 25 hours

```bash
# Alert check (run at 03:00 UTC, after backup completes)
0 3 * * * test $(find /backups/securedocs -name "db_*.sql.gz" -mtime -1 | wc -l) -ge 1 \
          || echo "BACKUP MISSING: $(date)" | mail -s "Backup Alert" admin@example.com
```

---

## 10. Retention and Disposal

| Retention Period | Action |
|---|---|
| Last 7 days | Retained on local server (automated rolling deletion by `backup.sh`) |
| Last 30 days (offsite) | Retained on Railway volume snapshots or cloud storage |
| Older than 30 days | Automatically deleted by cloud provider lifecycle policy |

Disposal of backup archives containing sensitive data must use secure deletion (`shred` or equivalent) to prevent data recovery.

---

## 11. Policy Compliance

Any failure to perform backups, perform monthly restore tests, or store backups securely will be treated as a policy violation. Repeated violations will be escalated to the course instructor.

---

## 12. Policy Review

This policy is reviewed **annually** (each November) or immediately following:
- A failed restore during an actual incident
- A change in system architecture affecting backed-up components
- A change in RTO/RPO requirements

**Reviewed by:** Security Administrator  
**Approved by:** Project Team

---

## 13. References

- NIST SP 800-34 Rev. 1 — Contingency Planning Guide for Federal Information Systems
- NIST SP 800-53 Rev. 5 — CP-9 (System Backup), CP-10 (System Recovery and Reconstitution)
- ISO/IEC 27001:2013 — Annex A.12.3 (Information Backup)
- PostgreSQL Documentation — `pg_dump` and `pg_restore`
