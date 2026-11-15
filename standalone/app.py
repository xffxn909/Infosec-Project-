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

Then open http://127.0.0.1:5000
Default admin credentials: admin / Admin@1234  (change on first run!)
"""

import os
import io
import datetime
from pathlib import Path
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, flash, send_from_directory,
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

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

UPLOAD_DIR = Path("uploads")
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
# HTML Templates (inline for self-contained single-file demo)
# ─────────────────────────────────────────────────────────────────────────────

def render_page(title, content, user=None, **ctx):
    """Render a full page with nav, flashes, and body content."""
    NAV = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureDoc – {title}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#f0f4f8;color:#222}}
  nav{{background:#1a1a2e;color:#fff;padding:12px 24px;display:flex;align-items:center;gap:16px}}
  nav a{{color:#a0c4ff;text-decoration:none;font-size:.9rem}}
  nav a:hover{{color:#fff}}
  nav .brand{{font-weight:700;font-size:1.1rem;color:#fff;margin-right:auto}}
  .container{{max-width:1000px;margin:32px auto;padding:0 16px}}
  h1{{font-size:1.5rem;margin-bottom:16px;color:#1a1a2e}}
  h2{{font-size:1.1rem;margin:24px 0 8px;color:#333}}
  .card{{background:#fff;border-radius:8px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:20px}}
  .btn{{display:inline-block;padding:8px 18px;border-radius:5px;border:none;cursor:pointer;font-size:.9rem;text-decoration:none}}
  .btn-primary{{background:#1a1a2e;color:#fff}}
  .btn-success{{background:#2d7a4f;color:#fff}}
  .btn-danger{{background:#b91c1c;color:#fff}}
  .btn-warning{{background:#b45309;color:#fff}}
  .btn-sm{{padding:4px 10px;font-size:.8rem}}
  .alert{{padding:10px 16px;border-radius:5px;margin-bottom:12px;font-size:.9rem}}
  .alert-danger{{background:#fee2e2;color:#991b1b}}
  .alert-success{{background:#dcfce7;color:#166534}}
  .alert-warning{{background:#fef3c7;color:#92400e}}
  .alert-info{{background:#dbeafe;color:#1e40af}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #e5e7eb}}
  th{{background:#f8fafc;font-weight:600}}
  tr:hover{{background:#f1f5f9}}
  form label{{display:block;font-size:.85rem;font-weight:600;margin:12px 0 4px}}
  form input,form select{{width:100%;padding:8px;border:1px solid #d1d5db;border-radius:4px;font-size:.9rem}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}}
  .badge-green{{background:#dcfce7;color:#166534}}
  .badge-red{{background:#fee2e2;color:#991b1b}}
  .badge-yellow{{background:#fef3c7;color:#92400e}}
  .badge-blue{{background:#dbeafe;color:#1e40af}}
  .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
  pre{{background:#1e293b;color:#e2e8f0;padding:16px;border-radius:6px;overflow:auto;font-size:.8rem;white-space:pre-wrap}}
</style>
</head>
<body>"""

    return render_template_string(
        NAV + """
<nav>
  <span class="brand">🔒 SecureDoc</span>
  {% if user %}
    <a href="{{ url_for('dashboard') }}">Dashboard</a>
    <a href="{{ url_for('documents_page') }}">Documents</a>
    <a href="{{ url_for('audit_page') }}">Audit Log</a>
    {% if user.role == 'admin' %}
      <a href="{{ url_for('admin_page') }}">Admin</a>
      <a href="{{ url_for('risk_page') }}">Risk Report</a>
      <a href="{{ url_for('backup_page') }}">Backups</a>
    {% endif %}
    <a href="{{ url_for('logout') }}" style="margin-left:auto;color:#fca5a5">Logout ({{ user.username }})</a>
  {% endif %}
</nav>
<div class="container">
  {% for cat, msg in get_flashed_messages(with_categories=True) %}
    <div class="alert alert-{{ cat }}">{{ msg }}</div>
  {% endfor %}
""" + content + """
</div></body></html>""",
        title=title, user=user, **ctx
    )

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

    return render_page("Login", """
<div style="max-width:400px;margin:60px auto">
<div class="card">
  <h1>🔐 Sign In</h1>
  <form method="post">
    <label>Username</label>
    <input name="username" required autofocus>
    <label>Password</label>
    <input type="password" name="password" required>
    <label>MFA Code (if enabled)</label>
    <input name="totp" placeholder="6-digit code" maxlength="6">
    <button class="btn btn-primary" style="width:100%;margin-top:16px">Sign In</button>
  </form>
</div>
</div>
""", user=None)


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

    return render_page("Dashboard", """
<h1>Dashboard</h1>
<div class="grid2">
  <div class="card"><h2>Total Documents</h2><p style="font-size:2rem;font-weight:700">{{ total }}</p></div>
  <div class="card"><h2>Digitally Signed</h2><p style="font-size:2rem;font-weight:700;color:#2d7a4f">{{ signed }}</p></div>
  <div class="card"><h2>Tampered / Alert</h2>
    <p style="font-size:2rem;font-weight:700;color:{% if tampered %}#b91c1c{% else %}#2d7a4f{% endif %}">{{ tampered }}</p>
  </div>
  <div class="card"><h2>Your Role</h2>
    <p style="font-size:1.5rem;font-weight:700">
      <span class="badge badge-blue">{{ user.role | upper }}</span>
    </p>
  </div>
</div>
<div class="card">
  <h2>Recent Documents</h2>
  <table>
    <tr><th>Filename</th><th>Uploaded by</th><th>Signed by</th><th>Date</th><th>Action</th></tr>
    {% for d in docs[:10] %}
    <tr>
      <td>{{ d.filename }}</td>
      <td>{{ d.uploader }}</td>
      <td>{{ d.signed_by or '—' }}</td>
      <td>{{ d.created_at }}</td>
      <td><a href="{{ url_for('verify_doc', stored_name=d.stored_name) }}" class="btn btn-sm btn-primary">Verify</a></td>
    </tr>
    {% endfor %}
  </table>
  <a href="{{ url_for('documents_page') }}" class="btn btn-primary" style="margin-top:12px">All Documents →</a>
</div>
""", user=user, total=total, signed=signed, tampered=tampered_count, docs=docs)


@app.route("/documents")
@login_required
def documents_page():
    user = get_current_user()
    docs = doc_svc.list_docs(user["username"], user["role"])
    return render_page("Documents", """
<h1>Documents</h1>
<div class="card" style="margin-bottom:16px">
  <h2>Upload New Document</h2>
  <form method="post" action="{{ url_for('upload_doc') }}" enctype="multipart/form-data">
    <label>Select File</label>
    <input type="file" name="file" required>
    <button class="btn btn-success" style="margin-top:12px">Upload &amp; Hash</button>
  </form>
</div>
<div class="card">
  <table>
    <tr><th>Filename</th><th>SHA-256 (first 16)</th><th>Uploader</th><th>Signed by</th><th>Date</th><th>Actions</th></tr>
    {% for d in docs %}
    <tr>
      <td>{{ d.filename }}</td>
      <td><code>{{ d.sha256[:16] }}…</code></td>
      <td>{{ d.uploader }}</td>
      <td>{% if d.signed_by %}<span class="badge badge-green">{{ d.signed_by }}</span>{% else %}—{% endif %}</td>
      <td>{{ d.created_at }}</td>
      <td>
        {% if not d.signed_by %}
        <a href="{{ url_for('sign_doc', stored_name=d.stored_name) }}" class="btn btn-sm btn-warning">Sign</a>
        {% endif %}
        <a href="{{ url_for('verify_doc', stored_name=d.stored_name) }}" class="btn btn-sm btn-primary">Verify</a>
      </td>
    </tr>
    {% endfor %}
  </table>
</div>
""", user=user, docs=docs)


@app.route("/upload", methods=["POST"])
@login_required
def upload_doc():
    user = get_current_user()
    if "file" not in request.files or request.files["file"].filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("documents_page"))

    f = request.files["file"]
    import tempfile, shutil
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
        flash(f"Document signed with your ECDSA key. ✅", "success")
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

    return render_page("Verification", """
<h1>Verification Report</h1>
<div class="card">
  <table>
    {% for k, v in result.items() %}
    <tr>
      <th style="width:200px">{{ k }}</th>
      <td>
        {% if v == True %}<span class="badge badge-green">✅ True</span>
        {% elif v == False %}<span class="badge badge-red">❌ False</span>
        {% else %}{{ v }}{% endif %}
      </td>
    </tr>
    {% endfor %}
  </table>
  <a href="{{ url_for('documents_page') }}" class="btn btn-primary" style="margin-top:16px">← Back</a>
</div>
""", user=user, result=result)


@app.route("/audit")
@login_required
def audit_page():
    user = get_current_user()
    if not auth_mod.has_permission(user, "manager"):
        flash("Managers and admins only.", "danger")
        return redirect(url_for("dashboard"))
    logs = db.get_audit_log(200)
    return render_page("Audit Log", """
<h1>Audit Log</h1>
<div class="card">
  <table>
    <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th><th>Detail</th></tr>
    {% for log in logs %}
    <tr>
      <td style="white-space:nowrap">{{ log.timestamp }}</td>
      <td>{{ log.actor }}</td>
      <td><code>{{ log.action }}</code></td>
      <td>{{ log.target or '—' }}</td>
      <td>{{ log.ip_address or '—' }}</td>
      <td style="font-size:.75rem;max-width:300px">{{ log.detail or '' }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
""", user=user, logs=logs)


@app.route("/admin", methods=["GET", "POST"])
@role_required("admin")
def admin_page():
    user = get_current_user()
    int_key_path = PKI_DIR / "intermediate_ca.key"
    int_cert_path = PKI_DIR / "intermediate_ca.crt"
    message = None

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
            # capture output
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                demo_hash_comparison()
            flash(buf.getvalue(), "info")

    with db.get_conn() as conn:
        users = [dict(r) for r in conn.execute("SELECT username, role, created_at, active FROM users").fetchall()]

    return render_page("Admin", """
<h1>Admin Panel</h1>
<div class="grid2">
  <div class="card">
    <h2>Create User</h2>
    <form method="post">
      <input type="hidden" name="action" value="create_user">
      <label>Username</label><input name="username" required>
      <label>Password</label><input type="password" name="password" required>
      <label>Role</label>
      <select name="role">
        <option value="staff">Staff</option>
        <option value="manager">Manager</option>
        <option value="admin">Admin</option>
      </select>
      <button class="btn btn-success" style="margin-top:12px">Create</button>
    </form>
  </div>
  <div class="card">
    <h2>Revoke Certificate</h2>
    <form method="post">
      <input type="hidden" name="action" value="revoke_cert">
      <label>Username to Revoke</label><input name="target_user" required>
      <button class="btn btn-danger" style="margin-top:12px">Revoke &amp; Update CRL</button>
    </form>
    <hr style="margin:16px 0">
    <h2>Security Demo</h2>
    <form method="post">
      <input type="hidden" name="action" value="hash_demo">
      <button class="btn btn-warning">MD5 vs Argon2 Speed Test</button>
    </form>
  </div>
</div>
<div class="card">
  <h2>Users</h2>
  <table>
    <tr><th>Username</th><th>Role</th><th>Created</th><th>Active</th></tr>
    {% for u in users %}
    <tr>
      <td>{{ u.username }}</td>
      <td><span class="badge badge-blue">{{ u.role }}</span></td>
      <td>{{ u.created_at }}</td>
      <td>{% if u.active %}<span class="badge badge-green">Yes</span>{% else %}<span class="badge badge-red">No</span>{% endif %}</td>
    </tr>
    {% endfor %}
  </table>
</div>
""", user=user, users=users)


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
    return render_page("Backups", """
<h1>Backup &amp; Recovery</h1>
<div class="grid2">
  <div class="card">
    <h2>Create Backup</h2>
    <form method="post">
      <input type="hidden" name="action" value="create">
      <button class="btn btn-success">🗄️ Create Backup Now</button>
    </form>
  </div>
  <div class="card">
    <h2>Restore</h2>
    <form method="post">
      <input type="hidden" name="action" value="restore">
      <label>Select Archive</label>
      <select name="archive">
        {% for b in backups %}<option>{{ b.name }}</option>{% endfor %}
      </select>
      <button class="btn btn-warning" style="margin-top:12px">⚡ Restore &amp; Time It</button>
    </form>
  </div>
</div>
<div class="card">
  <h2>Backup Archives</h2>
  <table>
    <tr><th>Archive</th><th>Size</th></tr>
    {% for b in backups %}
    <tr><td>{{ b.name }}</td><td>{{ (b.stat().st_size // 1024) }} KB</td></tr>
    {% endfor %}
  </table>
  <p style="margin-top:12px;font-size:.85rem;color:#555">
    SLA: Max downtime 2 h/day · Restore target: &lt; 1 h
  </p>
</div>
""", user=user, backups=backups, restore_time=restore_time)


@app.route("/risk")
@role_required("admin")
def risk_page():
    user = get_current_user()
    scored = risk_mod.compute_scores(risk_mod.RISK_REGISTER)

    return render_page("Risk Assessment", """
<h1>Risk Assessment (NIST SP 800-30)</h1>

<div class="card">
  <h2>Asset Register</h2>
  <table>
    <tr><th>ID</th><th>Asset</th><th>Type</th><th>Value</th></tr>
    {% for a in assets %}
    <tr><td>{{ a.id }}</td><td>{{ a.name }}</td><td>{{ a.type }}</td>
    <td>
      {% if a.value == 'Critical' %}<span class="badge badge-red">Critical</span>
      {% elif a.value == 'High' %}<span class="badge badge-yellow">High</span>
      {% else %}<span class="badge badge-blue">{{ a.value }}</span>{% endif %}
    </td></tr>
    {% endfor %}
  </table>
</div>

<div class="card">
  <h2>Risk Register</h2>
  <table>
    <tr><th>ID</th><th>Threat</th><th>Score Before</th><th>Rating</th><th>Score After</th><th>Rating</th><th>Control</th></tr>
    {% for r in risks %}
    <tr>
      <td>{{ r.id }}</td>
      <td>{{ r.threat_id }}</td>
      <td><b>{{ r.score_before }}</b></td>
      <td>
        {% if r.rating_before == 'CRITICAL' %}<span class="badge badge-red">CRITICAL</span>
        {% elif r.rating_before == 'HIGH' %}<span class="badge badge-yellow">HIGH</span>
        {% elif r.rating_before == 'MEDIUM' %}<span class="badge badge-blue">MEDIUM</span>
        {% else %}<span class="badge badge-green">LOW</span>{% endif %}
      </td>
      <td><b>{{ r.score_after }}</b></td>
      <td>
        {% if r.rating_after == 'CRITICAL' %}<span class="badge badge-red">CRITICAL</span>
        {% elif r.rating_after == 'HIGH' %}<span class="badge badge-yellow">HIGH</span>
        {% elif r.rating_after == 'MEDIUM' %}<span class="badge badge-blue">MEDIUM</span>
        {% else %}<span class="badge badge-green">LOW</span>{% endif %}
      </td>
      <td style="font-size:.8rem">{{ r.control }}</td>
    </tr>
    {% endfor %}
  </table>
</div>

<div class="card">
  <h2>Policies</h2>
  <pre>{{ key_policy }}</pre>
  <pre>{{ backup_policy }}</pre>
</div>

<div class="card">
  <h2>Generate Full Text Report</h2>
  <a href="{{ url_for('risk_report_download') }}" class="btn btn-primary">📄 Download Report</a>
</div>
""", user=user, assets=risk_mod.ASSET_REGISTER, risks=scored,
     key_policy=risk_mod.PRIVATE_KEY_POLICY,
     backup_policy=risk_mod.BACKUP_RECOVERY_POLICY)


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
    os.chdir(Path(__file__).parent)   # ensure relative paths work
    bootstrap()
    print("\n[App] Starting SecureDoc on http://127.0.0.1:5000")
    print("[App] Login: admin / Admin@1234")
    app.run(debug=False, host="127.0.0.1", port=5000)
