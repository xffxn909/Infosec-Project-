"""
database.py
===========
SQLite-backed storage for users, documents, audit logs, and revoked certs.
No external DB server needed – runs entirely in the lab.
"""

import sqlite3
import datetime
from pathlib import Path

DB_PATH = Path("secure_doc.db")


def get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,          -- Argon2 hash
            role        TEXT NOT NULL DEFAULT 'staff',  -- admin | manager | staff
            totp_secret TEXT,                   -- MFA TOTP secret (base32)
            cert_serial TEXT,                   -- Their signing cert serial
            created_at  TEXT DEFAULT (datetime('now')),
            active      INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS documents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            filename     TEXT NOT NULL,
            stored_name  TEXT NOT NULL UNIQUE,  -- UUID-based disk filename
            uploader     TEXT NOT NULL,
            sha256       TEXT NOT NULL,
            signed_by    TEXT,                  -- username who signed
            sig_valid    INTEGER DEFAULT 0,     -- 1 = verified good
            created_at   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(uploader) REFERENCES users(username)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            actor      TEXT NOT NULL,
            action     TEXT NOT NULL,
            target     TEXT,
            detail     TEXT,
            ip_address TEXT,
            timestamp  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS revoked_certs (
            serial     TEXT PRIMARY KEY,
            revoked_by TEXT NOT NULL,
            reason     TEXT,
            revoked_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            username   TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
        );
        """)
    print(f"[DB] Database initialized at {DB_PATH.resolve()}")


# ─── Users ────────────────────────────────────────────────────────────────────

def create_user(username: str, password_hash: str, role: str = "staff",
                totp_secret: str = None, cert_serial: str = None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password, role, totp_secret, cert_serial) VALUES (?,?,?,?,?)",
            (username, password_hash, role, totp_secret, cert_serial),
        )


def get_user(username: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        return dict(row) if row else None


def update_user_cert(username: str, cert_serial: str):
    with get_conn() as conn:
        conn.execute("UPDATE users SET cert_serial=? WHERE username=?", (cert_serial, username))


# ─── Documents ────────────────────────────────────────────────────────────────

def add_document(filename: str, stored_name: str, uploader: str, sha256: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO documents (filename, stored_name, uploader, sha256) VALUES (?,?,?,?)",
            (filename, stored_name, uploader, sha256),
        )


def get_document(stored_name: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM documents WHERE stored_name=?", (stored_name,)).fetchone()
        return dict(row) if row else None


def list_documents(uploader: str = None) -> list[dict]:
    with get_conn() as conn:
        if uploader:
            rows = conn.execute(
                "SELECT * FROM documents WHERE uploader=? ORDER BY created_at DESC", (uploader,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM documents ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def mark_signed(stored_name: str, signed_by: str, sig_valid: bool):
    with get_conn() as conn:
        conn.execute(
            "UPDATE documents SET signed_by=?, sig_valid=? WHERE stored_name=?",
            (signed_by, 1 if sig_valid else 0, stored_name),
        )


# ─── Audit Log ────────────────────────────────────────────────────────────────

def audit(actor: str, action: str, target: str = None, detail: str = None, ip: str = None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, detail, ip_address) VALUES (?,?,?,?,?)",
            (actor, action, target, detail, ip),
        )


def get_audit_log(limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ─── Revoked Certs ────────────────────────────────────────────────────────────

def revoke_cert(serial: str, revoked_by: str, reason: str = ""):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_certs (serial, revoked_by, reason) VALUES (?,?,?)",
            (serial, revoked_by, reason),
        )


def is_cert_revoked(serial: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM revoked_certs WHERE serial=?", (serial,)).fetchone()
        return row is not None


# ─── Sessions ─────────────────────────────────────────────────────────────────

def create_session(token: str, username: str, ttl_minutes: int = 60):
    expires = (
        datetime.datetime.utcnow() + datetime.timedelta(minutes=ttl_minutes)
    ).isoformat()
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token, username, expires_at) VALUES (?,?,?)",
            (token, username, expires),
        )


def get_session(token: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token=? AND expires_at > datetime('now')", (token,)
        ).fetchone()
        return dict(row) if row else None


def delete_session(token: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))


if __name__ == "__main__":
    init_db()
    print("[DB] Schema ready.")
