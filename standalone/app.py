"""
app.py
======
Flask Web Application – Secure Document Management & E-Signature System
Ties together all modules:
  - PKI / crypto (pki_manager.py)
  - Auth + RBAC + MFA (auth.py)
  - Document upload / sign / verify (document_service.py)
  - Backup & availability (backup_service.py)
  - Risk assessment report (risk_assessment.py)
  - Audit log viewer

Run:
    python app.py
    # or from project root: python standalone/app.py

Then open http://127.0.0.1:5000
Default admin credentials: admin / Admin@1234
"""

import os
import sys
from pathlib import Path
from functools import wraps

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from flask import (
    Flask, request, redirect, url_for, session,
    render_template, flash, send_from_directory,
    jsonify, abort,
)

import database as db
import auth as auth_mod
import document_service as doc_svc
import backup_service as backup_svc
import risk_assessment as risk_mod
from pki_manager import (
    create_root_ca, create_intermediate_ca,
    issue_user_cert, build_crl,
    hash_password, demo_hash_comparison,
    PKI_DIR,
)

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
)
app.secret_key = os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def bootstrap():
    """Create DB, PKI hierarchy, and default admin on first run."""
    db.init_db()

    # Create PKI if not already done
    root_key_path = PKI_DIR / "root_ca.key"
    root_cert_path = PKI_DIR / "root_ca.crt"
    int_key_path = PKI_DIR / "intermediate_ca.key"
    int_cert_path = PKI_DIR / "intermediate_ca.crt"

    if not root_cert_path.exists():
        print("[Bootstrap] Building PKI hierarchy…")
        root_key, root_cert = create_root_ca()
        int_key, int_cert = create_intermediate_ca(root_key, root_cert)
    else:
        from pki_manager import load_private_key, load_cert
        root_key = load_private_key(root_key_path)
        root_cert = load_cert(root_cert_path)
        int_key = load_private_key(int_key_path)
        int_cert = load_cert(int_cert_path)

    # Default admin user
    if not db.get_user("admin"):
        pw_hash = hash_password("Admin@1234")
        totp_secret = auth_mod.generate_totp_secret()
        db.create_user("admin", pw_hash, role="admin", totp_secret=totp_secret)
        issue_user_cert("admin", int_key, int_cert)
        db.update_user_cert("admin", "admin-cert")
        print(f"[Bootstrap] Admin created. TOTP URI: {auth_mod.get_totp_uri(totp_secret, 'admin')}")
        print("[Bootstrap] Default password: Admin@1234  — CHANGE THIS!")

    return int_key, int_cert


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_current_user():
    token = session.get("token")
    if not token:
        return None
    return auth_mod.get_current_user(token)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please log in.", "warning")
            return redirect(url_for("login_page"))
        return fn(*args, **kwargs)
    return wrapper


def role_required(min_role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("login_page"))
            if not auth_mod.has_permission(user, min_role):
                flash(f"You need '{min_role}' role for this.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    user = get_current_user()
    if user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp = request.form.get("totp", "").strip() or None
        ip = request.remote_addr
        try:
            token = auth_mod.login(username, password, totp_code=totp, ip=ip)
            session["token"] = token
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("dashboard"))
        except auth_mod.AuthError as e:
            flash(str(e), "danger")

    return render_template("login.html", title="Login", user=None)


@app.route("/logout")
def logout():
    token = session.pop("token", None)
    if token:
        auth_mod.logout(token)
    flash("Signed out.", "info")
    return redirect(url_for("login_page"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    docs = doc_svc.list_docs(user["username"], user["role"])
    total = len(docs)
    signed = sum(1 for d in docs if d.get("signed_by"))
    tampered_count = 0
    for d in docs:
        fp = UPLOAD_DIR / d["stored_name"]
        if fp.exists():
            from pki_manager import tamper_check
            if not tamper_check(fp, d["sha256"]):
                tampered_count += 1

    return render_template(
        "dashboard.html",
        title="Dashboard",
        user=user,
        total=total,
        signed=signed,
        tampered=tampered_count,
        docs=docs,
    )


@app.route("/documents")
@login_required
def documents_page():
    user = get_current_user()
    docs = doc_svc.list_docs(user["username"], user["role"])
    return render_template(
        "documents.html",
        title="Documents",
        user=user,
        docs=docs,
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload_doc():
    user = get_current_user()
    if "file" not in request.files or request.files["file"].filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("documents_page"))

    f = request.files["file"]
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(f.filename).suffix) as tmp:
        f.save(tmp.name)
        tmp_path = Path(tmp.name)

    try:
        doc = doc_svc.upload_document(tmp_path, uploader=user["username"], ip=request.remote_addr)
        flash(f"Uploaded '{f.filename}' — SHA-256: {doc['sha256'][:32]}…", "success")
    finally:
        tmp_path.unlink(missing_ok=True)
    return redirect(url_for("documents_page"))


@app.route("/sign/<stored_name>")
@login_required
def sign_doc(stored_name):
    user = get_current_user()
    try:
        doc_svc.sign_doc(stored_name, signer_username=user["username"], ip=request.remote_addr)
        flash("Document signed with your ECDSA key. ✅", "success")
    except (FileNotFoundError, PermissionError, ValueError) as e:
        flash(str(e), "danger")
    return redirect(url_for("documents_page"))


@app.route("/verify/<stored_name>")
@login_required
def verify_doc(stored_name):
    user = get_current_user()
    try:
        result = doc_svc.verify_doc(stored_name, verifier=user["username"], ip=request.remote_addr)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("documents_page"))

    return render_template(
        "verify.html",
        title="Verification",
        user=user,
        result=result,
    )


@app.route("/audit")
@login_required
def audit_page():
    user = get_current_user()
    if not auth_mod.has_permission(user, "manager"):
        flash("Managers and admins only.", "danger")
        return redirect(url_for("dashboard"))
    logs = db.get_audit_log(200)
    return render_template(
        "audit.html",
        title="Audit Log",
        user=user,
        logs=logs,
    )


@app.route("/admin", methods=["GET", "POST"])
@role_required("admin")
def admin_page():
    user = get_current_user()
    int_key_path = PKI_DIR / "intermediate_ca.key"
    int_cert_path = PKI_DIR / "intermediate_ca.crt"

    if request.method == "POST":
        action = request.form.get("action")
        if action == "create_user":
            uname = request.form.get("username", "").strip()
            pw = request.form.get("password", "")
            role = request.form.get("role", "staff")
            if uname and pw:
                try:
                    totp_secret = auth_mod.generate_totp_secret()
                    pw_hash = hash_password(pw)
                    db.create_user(uname, pw_hash, role=role, totp_secret=totp_secret)
                    # Issue signing cert
                    from pki_manager import load_private_key, load_cert
                    int_key = load_private_key(int_key_path)
                    int_cert_obj = load_cert(int_cert_path)
                    issue_user_cert(uname, int_key, int_cert_obj)
                    db.update_user_cert(uname, uname + "-cert")
                    totp_uri = auth_mod.get_totp_uri(totp_secret, uname)
                    message = f"User '{uname}' created. TOTP URI: {totp_uri}"
                    flash(message, "success")
                    db.audit(user["username"], "CREATE_USER", target=uname, ip=request.remote_addr)
                except Exception as e:
                    flash(str(e), "danger")

        elif action == "revoke_cert":
            target_user = request.form.get("target_user", "").strip()
            if target_user:
                cert_path = PKI_DIR / "users" / target_user / "signing.crt"
                if cert_path.exists():
                    from pki_manager import load_cert, load_private_key
                    cert = load_cert(cert_path)
                    int_key = load_private_key(int_key_path)
                    int_cert_obj = load_cert(int_cert_path)
                    db.revoke_cert(hex(cert.serial_number), revoked_by=user["username"])
                    build_crl(int_key, int_cert_obj, [cert.serial_number])
                    flash(f"Certificate for '{target_user}' revoked and CRL updated.", "warning")
                    db.audit(user["username"], "REVOKE_CERT", target=target_user, ip=request.remote_addr)
                else:
                    flash("Certificate not found.", "danger")

        elif action == "hash_demo":
            import io
            import contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                demo_hash_comparison()
            flash(buf.getvalue(), "info")

    with db.get_conn() as conn:
        users = [dict(r) for r in conn.execute("SELECT username, role, created_at, active FROM users").fetchall()]

    return render_template(
        "admin.html",
        title="Admin",
        user=user,
        users=users,
    )


@app.route("/backup", methods=["GET", "POST"])
@role_required("admin")
def backup_page():
    user = get_current_user()
    restore_time = None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            archive = backup_svc.create_backup(actor=user["username"])
            flash(f"Backup created: {archive.name}", "success")
        elif action == "restore":
            archive_name = request.form.get("archive")
            if archive_name:
                archive_path = Path("backups") / archive_name
                restore_time = backup_svc.restore_backup(archive_path, actor=user["username"])
                flash(f"Restored in {restore_time:.2f}s  {'✅ Within SLA' if restore_time < 3600 else '❌ SLA Breached'}", "success")

    backups = backup_svc.list_backups()
    return render_template(
        "backups.html",
        title="Backups",
        user=user,
        backups=backups,
        restore_time=restore_time,
    )


@app.route("/risk")
@role_required("admin")
def risk_page():
    user = get_current_user()
    scored = risk_mod.compute_scores(risk_mod.RISK_REGISTER)

    return render_template(
        "risk.html",
        title="Risk Assessment",
        user=user,
        assets=risk_mod.ASSET_REGISTER,
        risks=scored,
        key_policy=risk_mod.PRIVATE_KEY_POLICY,
        backup_policy=risk_mod.BACKUP_RECOVERY_POLICY,
    )


@app.route("/risk/report")
@role_required("admin")
def risk_report_download():
    report_path = risk_mod.generate_report()
    return send_from_directory(
        str(report_path.parent),
        report_path.name,
        as_attachment=True,
        mimetype="text/plain",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.chdir(BASE_DIR)   # ensure relative paths work
    bootstrap()
    print("\n[App] Starting SecureDoc on http://127.0.0.1:5000")
    print("[App] Login: admin / Admin@1234")
    app.run(debug=False, host="127.0.0.1", port=5000)
