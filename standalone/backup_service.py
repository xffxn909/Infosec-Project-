"""
backup_service.py
=================
Module 1 – Availability Controls
  - Automated daily backup (DB + uploads)
  - Timed restore test
  - Firewall / rate-limit helpers (Windows netsh commands)
"""

import os
import time
import shutil
import zipfile
import datetime
import subprocess
from pathlib import Path

from database import audit

BACKUP_DIR = Path("backups")
BACKUP_DIR.mkdir(exist_ok=True)

DB_PATH = Path("secure_doc.db")
UPLOAD_DIR = Path("uploads")


# ─────────────────────────────────────────────────────────────────────────────
# Backup
# ─────────────────────────────────────────────────────────────────────────────

def create_backup(actor: str = "SYSTEM") -> Path:
    """
    Zip the database and uploads directory into a timestamped backup archive.
    Returns the path to the created archive.
    """
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = BACKUP_DIR / f"backup_{ts}.zip"

    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if DB_PATH.exists():
            zf.write(DB_PATH, DB_PATH.name)

        if UPLOAD_DIR.exists():
            for f in UPLOAD_DIR.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(UPLOAD_DIR.parent))

    size_kb = archive_path.stat().st_size // 1024
    audit(actor, "BACKUP_CREATED", target=str(archive_path),
          detail=f"Size: {size_kb} KB")
    print(f"[Backup] Created: {archive_path} ({size_kb} KB)")
    return archive_path


def list_backups() -> list[Path]:
    return sorted(BACKUP_DIR.glob("backup_*.zip"), reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Restore
# ─────────────────────────────────────────────────────────────────────────────

def restore_backup(archive_path: Path, actor: str = "SYSTEM") -> float:
    """
    Restore from a backup zip. Measures and returns restore time in seconds.
    SLA target: < 3600 s (1 hour).
    """
    if not archive_path.exists():
        raise FileNotFoundError(f"Backup not found: {archive_path}")

    start = time.perf_counter()

    restore_tmp = Path("restore_tmp")
    restore_tmp.mkdir(exist_ok=True)

    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(restore_tmp)

    # Overwrite live DB
    restored_db = restore_tmp / DB_PATH.name
    if restored_db.exists():
        shutil.copy2(restored_db, DB_PATH)

    # Overwrite uploads
    restored_uploads = restore_tmp / UPLOAD_DIR.name
    if restored_uploads.exists():
        if UPLOAD_DIR.exists():
            shutil.rmtree(UPLOAD_DIR)
        shutil.copytree(restored_uploads, UPLOAD_DIR)

    shutil.rmtree(restore_tmp)
    elapsed = time.perf_counter() - start

    audit(actor, "RESTORE", target=str(archive_path),
          detail=f"Duration: {elapsed:.2f}s")
    sla_ok = elapsed < 3600
    print(f"[Backup] Restored in {elapsed:.2f}s  SLA ({'✅ OK' if sla_ok else '❌ BREACHED'})")
    return elapsed


# ─────────────────────────────────────────────────────────────────────────────
# Firewall Rules (Windows netsh / iptables concept; prints commands for review)
# ─────────────────────────────────────────────────────────────────────────────

def show_firewall_commands(app_port: int = 5000):
    """
    Print the Windows Firewall commands that should be applied in production.
    Does NOT execute them automatically — an admin must review and apply.
    """
    rules = [
        f'netsh advfirewall firewall add rule name="SecureDoc-Allow-HTTPS" protocol=TCP dir=in localport={app_port} action=allow',
        'netsh advfirewall firewall add rule name="SecureDoc-Block-Telnet" protocol=TCP dir=in localport=23 action=block',
        'netsh advfirewall firewall add rule name="SecureDoc-Block-FTP" protocol=TCP dir=in localport=21 action=block',
    ]
    print("\n[Firewall] Commands to apply (run as Administrator):")
    for r in rules:
        print(f"  {r}")
    return rules


def apply_firewall_rules(app_port: int = 5000):
    """Actually apply firewall rules (requires admin privileges)."""
    cmds = [
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name=SecureDoc-Allow-Port{app_port}",
         "protocol=TCP", "dir=in", f"localport={app_port}", "action=allow"],
    ]
    for cmd in cmds:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[Firewall] Rule applied: {' '.join(cmd)}")
        else:
            print(f"[Firewall] Failed (need admin?): {result.stderr.strip()}")


# ─────────────────────────────────────────────────────────────────────────────
# Availability Report
# ─────────────────────────────────────────────────────────────────────────────

def availability_report():
    backups = list_backups()
    print(f"\n[Availability] Backups on disk: {len(backups)}")
    for b in backups[:5]:
        size_kb = b.stat().st_size // 1024
        print(f"  {b.name}  ({size_kb} KB)")
    print(f"[Availability] Max allowed downtime: 2 h / working day")
    print(f"[Availability] Max restore time (SLA): 1 h")
    show_firewall_commands()


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from database import init_db
    init_db()

    print("=== Backup Service Self-Test ===")
    archive = create_backup(actor="admin")
    restore_time = restore_backup(archive, actor="admin")
    availability_report()
