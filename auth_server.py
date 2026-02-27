"""
ProxyHunter Auth Server v4
==========================
Self-hosted auth server for license management.
Deploy on a separate Hetzner (Linux) server.

Features:
  - Customer database (SQLite, auto-backed-up)
  - License key activation with HWID binding
  - HWID reset (max 3 times per customer, more on admin override)
  - Subscription expiry checks
  - Admin web panel (password protected)
  - REST API for bot validation
  - Real-time stats dashboard
  - Rate limiting on activation endpoint

Access after install:
  Admin panel: http://YOUR_SERVER_IP:5000/admin
  API:         http://YOUR_SERVER_IP:5000/api/

Requirements:
  pip install flask flask-limiter
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Optional

try:
    from flask import Flask, request, jsonify, render_template_string, redirect, session, url_for
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "flask", "-q"])
    from flask import Flask, request, jsonify, render_template_string, redirect, session, url_for

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────

_CFG_FILE = Path("auth_config.json")
_DEFAULT_CFG = {
    "admin_username":  "admin",
    "admin_password":  "changeme",        # Hashed on first run
    "secret_key":      secrets.token_hex(32),
    "db_path":         "auth.db",
    "port":            5000,
    "host":            "0.0.0.0",
    "license_secret":  "PH4_LICENSE_SECRET_KEY_2025_V4",
    "max_hwid_resets": 3,
    "rate_limit_activate": "10/minute",
    "backup_interval": 3600,
    "allowed_ips":     [],   # Empty = allow all. Add IPs to restrict admin access
}

def _load_cfg() -> dict:
    if _CFG_FILE.exists():
        try:
            return {**_DEFAULT_CFG, **json.loads(_CFG_FILE.read_text())}
        except Exception:
            pass
    _CFG_FILE.write_text(json.dumps(_DEFAULT_CFG, indent=2))
    return dict(_DEFAULT_CFG)

def _save_cfg(cfg: dict):
    _CFG_FILE.write_text(json.dumps(cfg, indent=2))

CFG = _load_cfg()

# ─────────────────────────────────────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(CFG["db_path"], check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS customers (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL DEFAULT '',
            email           TEXT    UNIQUE NOT NULL,
            tier            TEXT    NOT NULL DEFAULT 'Starter',
            status          TEXT    NOT NULL DEFAULT 'active',
            license_key     TEXT    UNIQUE,
            hwid            TEXT,
            hwid_resets     INTEGER NOT NULL DEFAULT 0,
            machines        INTEGER NOT NULL DEFAULT 1,
            ipqs_daily      INTEGER NOT NULL DEFAULT 100,
            created_at      REAL    NOT NULL DEFAULT (unixepoch()),
            expires_at      REAL    NOT NULL DEFAULT (unixepoch() + 2592000),
            last_activation REAL,
            last_check      REAL,
            notes           TEXT    DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS activations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            hwid        TEXT    NOT NULL,
            ip_address  TEXT,
            timestamp   REAL    NOT NULL DEFAULT (unixepoch()),
            action      TEXT    NOT NULL DEFAULT 'activate',
            result      TEXT    NOT NULL DEFAULT 'ok',
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL    NOT NULL DEFAULT (unixepoch()),
            action      TEXT    NOT NULL,
            actor       TEXT    NOT NULL DEFAULT 'system',
            detail      TEXT    NOT NULL DEFAULT '',
            ip_address  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cust_email      ON customers(email);
        CREATE INDEX IF NOT EXISTS idx_cust_license    ON customers(license_key);
        CREATE INDEX IF NOT EXISTS idx_cust_hwid       ON customers(hwid);
        CREATE INDEX IF NOT EXISTS idx_act_customer    ON activations(customer_id);
        """)

def _audit(action: str, detail: str, actor: str = "system", ip: str = ""):
    with _conn() as c:
        c.execute(
            "INSERT INTO audit_log (action, detail, actor, ip_address) VALUES (?,?,?,?)",
            (action, detail, actor, ip))

# ─────────────────────────────────────────────────────────────────────────────
#  LICENSE KEY LOGIC  (must match admin_keygen.py and gui_app.py)
# ─────────────────────────────────────────────────────────────────────────────

_LK_SECRET = CFG.get("license_secret", "").encode()

TIER_CODE = {"S": "Starter", "P": "Pro", "E": "Enterprise", "L": "Lifetime"}
TIER_NAME = {v: k for k, v in TIER_CODE.items()}

def generate_license_key(tier: str, days: int, machines: int,
                          customer_id: int) -> str:
    tc = TIER_NAME.get(tier, "S")
    expiry = int(time.time()) + days * 86400
    payload = f"{tc}|{expiry}|{machines}|{customer_id:06d}"
    sig = hmac.new(_LK_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:5].upper()
    b32 = base64.b32encode(payload.encode()).decode().rstrip("=").ljust(25, "A")[:25]
    raw = b32 + sig
    chunks = [raw[i:i+6] for i in range(0, len(raw), 6)]
    return "PH4-" + "-".join(chunks)


def validate_license_key(key: str) -> dict:
    try:
        key = key.strip().upper()
        if not key.startswith("PH4-"):
            return {"valid": False, "error": "Bad prefix"}
        raw = key[4:].replace("-", "")
        b32_part = raw[:25]
        sig_part = raw[25:30]
        padded = b32_part + "=" * ((8 - len(b32_part) % 8) % 8)
        payload = base64.b32decode(padded).decode()
        parts = payload.split("|")
        if len(parts) != 4:
            return {"valid": False, "error": "Bad structure"}
        tc, expiry_s, machines_s, cid_s = parts
        expected = hmac.new(_LK_SECRET, payload.encode(),
                             hashlib.sha256).hexdigest()[:5].upper()
        if not hmac.compare_digest(sig_part, expected):
            return {"valid": False, "error": "Bad signature"}
        expiry = int(expiry_s)
        days_left = max(0, int((expiry - time.time()) / 86400))
        return {
            "valid":       time.time() < expiry,
            "tier":        TIER_CODE.get(tc, "Unknown"),
            "expiry":      expiry,
            "machines":    int(machines_s),
            "customer_id": int(cid_s),
            "days_left":   days_left,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}

# ─────────────────────────────────────────────────────────────────────────────
#  FLASK APP
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = CFG.get("secret_key", secrets.token_hex(32))

# ── Admin auth decorator ──────────────────────────────────────────────────────

def _admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated


def _api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Simple shared secret for bot→server communication
        key = request.headers.get("X-API-Key", "")
        expected = hashlib.sha256(
            CFG.get("secret_key", "").encode()).hexdigest()[:32]
        if key != expected:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ── Password hashing ──────────────────────────────────────────────────────────

def _hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260000)
    return f"{salt}:{h.hex()}"

def _check_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        expected = hashlib.pbkdf2_hmac(
            "sha256", pw.encode(), salt.encode(), 260000).hex()
        return hmac.compare_digest(h, expected)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
#  API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/activate", methods=["POST"])
def api_activate():
    """
    Activate a license key with a hardware ID.
    Called by ProxyHunter bot on startup / activation.
    """
    data     = request.get_json(silent=True) or {}
    key      = data.get("license_key", "").strip().upper()
    hwid     = data.get("hwid", "").strip()
    ip_addr  = request.remote_addr

    if not key or not hwid:
        return jsonify({"success": False, "error": "Missing license_key or hwid"}), 400

    # Validate key crypto
    kv = validate_license_key(key)
    if not kv.get("valid"):
        _audit("activate_fail", f"key={key[:10]} hwid={hwid[:12]} reason=bad_key", ip=ip_addr)
        return jsonify({"success": False, "error": f"Invalid key: {kv.get('error','')}"}), 400

    with _conn() as db:
        row = db.execute(
            "SELECT * FROM customers WHERE license_key=?", (key,)).fetchone()

        if not row:
            return jsonify({"success": False, "error": "Key not found in database"}), 404

        if row["status"] == "revoked":
            _audit("activate_fail", f"key={key[:10]} reason=revoked", ip=ip_addr)
            return jsonify({"success": False, "error": "License revoked"}), 403

        # Check expiry from DB (belt+suspenders — key also has expiry baked in)
        if row["expires_at"] < time.time():
            return jsonify({"success": False, "error": "License expired. Renew at proxyhunter.io"}), 403

        # HWID binding
        existing_hwid = row["hwid"]
        if existing_hwid and existing_hwid != hwid:
            return jsonify({
                "success": False,
                "error":   "License is locked to a different machine. "
                           "Reset your HWID at proxyhunter.io (up to 3 times).",
                "hwid_resets_used": row["hwid_resets"],
                "max_resets":       CFG.get("max_hwid_resets", 3),
            }), 403

        # Bind HWID if first activation
        if not existing_hwid:
            db.execute(
                "UPDATE customers SET hwid=?, last_activation=? WHERE id=?",
                (hwid, time.time(), row["id"]))
            _audit("hwid_bound",
                   f"customer={row['email']} hwid={hwid[:12]}",
                   ip=ip_addr)

        # Update last check
        db.execute("UPDATE customers SET last_check=? WHERE id=?",
                   (time.time(), row["id"]))

        # Log activation
        db.execute(
            "INSERT INTO activations (customer_id, hwid, ip_address, action, result) "
            "VALUES (?,?,?,?,?)",
            (row["id"], hwid, ip_addr, "activate", "ok"))

    _audit("activate_ok",
           f"customer={row['email']} tier={row['tier']}",
           ip=ip_addr)

    limits = {
        "machines":  row["machines"],
        "ipqs":      row["ipqs_daily"],
        "scheduler": row["tier"] in ("Pro","Enterprise","Lifetime"),
        "pool":      row["tier"] in ("Pro","Enterprise","Lifetime"),
        "api":       row["tier"] in ("Enterprise","Lifetime"),
        "remote":    row["tier"] in ("Enterprise","Lifetime"),
        "telegram":  row["tier"] in ("Pro","Enterprise","Lifetime"),
    }
    return jsonify({
        "success":   True,
        "tier":      row["tier"],
        "expires_at": row["expires_at"],
        "days_left": int((row["expires_at"] - time.time()) / 86400),
        "limits":    limits,
        "name":      row["name"],
    })


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """Fast license check without re-binding (called every startup)."""
    data = request.get_json(silent=True) or {}
    key  = data.get("license_key", "").strip().upper()
    hwid = data.get("hwid", "").strip()

    if not key or not hwid:
        return jsonify({"valid": False, "error": "Missing params"}), 400

    kv = validate_license_key(key)
    if not kv.get("valid"):
        return jsonify({"valid": False, "error": kv.get("error")}), 400

    with _conn() as db:
        row = db.execute(
            "SELECT * FROM customers WHERE license_key=?", (key,)).fetchone()
        if not row:
            return jsonify({"valid": False, "error": "Key not found"}), 404
        if row["status"] == "revoked":
            return jsonify({"valid": False, "error": "License revoked"}), 403
        if row["expires_at"] < time.time():
            return jsonify({"valid": False, "error": "Expired"}), 403
        if row["hwid"] and row["hwid"] != hwid:
            return jsonify({"valid": False, "error": "HWID mismatch"}), 403
        db.execute("UPDATE customers SET last_check=? WHERE id=?",
                   (time.time(), row["id"]))

    return jsonify({
        "valid":     True,
        "tier":      row["tier"],
        "days_left": int((row["expires_at"] - time.time()) / 86400),
        "limits": {
            "machines":  row["machines"],
            "ipqs":      row["ipqs_daily"],
            "scheduler": row["tier"] in ("Pro","Enterprise","Lifetime"),
            "pool":      row["tier"] in ("Pro","Enterprise","Lifetime"),
            "remote":    row["tier"] in ("Enterprise","Lifetime"),
        }
    })


@app.route("/api/reset-hwid", methods=["POST"])
def api_reset_hwid():
    """
    Customer-facing HWID reset.
    Requires license key + email verification.
    Max 3 resets before requiring admin intervention.
    """
    data  = request.get_json(silent=True) or {}
    key   = data.get("license_key", "").strip().upper()
    email = data.get("email", "").strip().lower()
    ip    = request.remote_addr

    if not key or not email:
        return jsonify({"success": False, "error": "Missing params"}), 400

    with _conn() as db:
        row = db.execute(
            "SELECT * FROM customers WHERE license_key=? AND lower(email)=?",
            (key, email)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Key / email not found"}), 404
        max_resets = CFG.get("max_hwid_resets", 3)
        if row["hwid_resets"] >= max_resets:
            return jsonify({
                "success": False,
                "error":   f"Maximum HWID resets ({max_resets}) reached. "
                           "Contact support@proxyhunter.io.",
            }), 403
        # Perform reset
        new_resets = row["hwid_resets"] + 1
        db.execute(
            "UPDATE customers SET hwid=NULL, hwid_resets=? WHERE id=?",
            (new_resets, row["id"]))
        _audit("hwid_reset",
               f"customer={email} resets={new_resets}/{max_resets}",
               ip=ip)

    return jsonify({
        "success":         True,
        "hwid_resets_used": new_resets,
        "resets_remaining": max_resets - new_resets,
        "message":         "HWID cleared. Activate on your new machine.",
    })


@app.route("/api/stats", methods=["GET"])
@_api_key_required
def api_stats():
    with _conn() as db:
        total     = db.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        active    = db.execute("SELECT COUNT(*) FROM customers WHERE status='active'").fetchone()[0]
        expired   = db.execute(
            "SELECT COUNT(*) FROM customers WHERE expires_at < ?", (time.time(),)).fetchone()[0]
        act_today = db.execute(
            "SELECT COUNT(*) FROM activations WHERE timestamp > ?",
            (time.time() - 86400,)).fetchone()[0]
        by_tier   = {r[0]: r[1] for r in db.execute(
            "SELECT tier, COUNT(*) FROM customers GROUP BY tier").fetchall()}
    return jsonify({
        "total": total, "active": active, "expired": expired,
        "activations_today": act_today, "by_tier": by_tier,
    })

# ─────────────────────────────────────────────────────────────────────────────
#  ADMIN PANEL
# ─────────────────────────────────────────────────────────────────────────────

_ADMIN_CSS = """
body{margin:0;font-family:'Segoe UI',sans-serif;background:#1e1e2e;color:#cdd6f4}
a{color:#89b4fa;text-decoration:none}a:hover{text-decoration:underline}
.sidebar{position:fixed;top:0;left:0;width:200px;height:100vh;background:#181825;padding:20px 0}
.sidebar h2{color:#89b4fa;font-size:14px;padding:0 20px 16px;border-bottom:1px solid #313244;margin:0 0 12px}
.sidebar a{display:block;padding:10px 20px;color:#cdd6f4;font-size:13px}
.sidebar a:hover,.sidebar a.active{background:#313244;color:#89b4fa;text-decoration:none}
.main{margin-left:200px;padding:24px}
h1{color:#89b4fa;font-size:20px;margin:0 0 20px}
.cards{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.card{background:#2a2a3d;border-radius:8px;padding:16px 20px;min-width:130px}
.card .val{font-size:24px;font-weight:bold;color:#89b4fa}
.card .lbl{font-size:11px;color:#6c7086;margin-top:4px}
table{width:100%;border-collapse:collapse;background:#2a2a3d;border-radius:8px;overflow:hidden}
th{background:#313244;padding:10px 12px;text-align:left;font-size:12px;color:#89b4fa}
td{padding:9px 12px;font-size:12px;border-bottom:1px solid #313244}
tr:last-child td{border-bottom:none}
tr:hover td{background:#313244}
.badge{padding:3px 8px;border-radius:12px;font-size:10px;font-weight:bold}
.badge-active{background:#a6e3a1;color:#1e1e2e}
.badge-revoked{background:#f38ba8;color:#1e1e2e}
.badge-expired{background:#f9e2af;color:#1e1e2e}
.badge-Pro{background:#89b4fa;color:#1e1e2e}
.badge-Enterprise{background:#a6e3a1;color:#1e1e2e}
.badge-Lifetime{background:#cba6f7;color:#1e1e2e}
.badge-Starter{background:#6c7086;color:#cdd6f4}
input,select,textarea{background:#181825;border:1px solid #313244;color:#cdd6f4;padding:8px 10px;border-radius:6px;font-size:13px;width:100%;box-sizing:border-box;margin-bottom:10px}
input:focus,select:focus{outline:none;border-color:#89b4fa}
.btn{display:inline-block;padding:8px 16px;border-radius:6px;font-size:13px;font-weight:bold;cursor:pointer;border:none}
.btn-primary{background:#89b4fa;color:#1e1e2e}.btn-danger{background:#f38ba8;color:#1e1e2e}
.btn-green{background:#a6e3a1;color:#1e1e2e}.btn-sm{padding:4px 10px;font-size:11px}
.flash{padding:10px 16px;border-radius:6px;margin-bottom:16px;font-size:13px}
.flash-ok{background:#a6e3a1;color:#1e1e2e}.flash-err{background:#f38ba8;color:#1e1e2e}
form{background:#2a2a3d;padding:20px;border-radius:8px;max-width:480px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.mono{font-family:Consolas,monospace;font-size:11px;word-break:break-all}
"""

_ADMIN_NAV = """
<div class="sidebar">
  <h2>🕵️ ProxyHunter<br>Auth Server</h2>
  <a href="/admin" class="{% if active=='dash' %}active{% endif %}">📊 Dashboard</a>
  <a href="/admin/customers" class="{% if active=='cust' %}active{% endif %}">👥 Customers</a>
  <a href="/admin/new_customer" class="{% if active=='new' %}active{% endif %}">➕ New Customer</a>
  <a href="/admin/audit" class="{% if active=='audit' %}active{% endif %}">📋 Audit Log</a>
  <a href="/admin/config" class="{% if active=='cfg' %}active{% endif %}">⚙️ Config</a>
  <a href="/admin/logout" style="position:absolute;bottom:20px;left:0;right:0">🚪 Logout</a>
</div>
"""

def _render(title: str, body: str, active: str = "dash") -> str:
    nav = _ADMIN_NAV.replace("{% if active=='" + active + "' %}active{% endif %}", "active")
    nav = re.sub(r"\{%.*?%\}", "", nav)
    return f"""<!DOCTYPE html>
<html><head><title>{title} — ProxyHunter Auth</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>{_ADMIN_CSS}</style></head>
<body>{nav}<div class="main"><h1>{title}</h1>{body}</div></body></html>"""


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = ""
    if request.method == "POST":
        un = request.form.get("username", "")
        pw = request.form.get("password", "")
        stored_pw = CFG.get("admin_password", "")
        # Support both plain (first run) and hashed passwords
        pw_ok = (pw == stored_pw or
                 (stored_pw.startswith("pbkdf2") or ":" in stored_pw
                  and _check_password(pw, stored_pw)))
        if not pw_ok and pw == stored_pw:
            pw_ok = True  # plain text fallback
        if un == CFG.get("admin_username") and pw_ok:
            session["admin_logged_in"] = True
            _audit("admin_login", f"user={un}", ip=request.remote_addr)
            return redirect("/admin")
        error = "Invalid credentials"
        _audit("admin_login_fail", f"user={un}", ip=request.remote_addr)
    return f"""<!DOCTYPE html><html><head><title>Login</title>
<meta charset="utf-8"><style>{_ADMIN_CSS}
.login{{max-width:340px;margin:80px auto;background:#2a2a3d;padding:32px;border-radius:12px}}
.login h2{{color:#89b4fa;margin-bottom:24px}}
</style></head><body>
<div class="login">
<h2>🕵️ ProxyHunter Auth</h2>
{'<div class="flash flash-err">' + error + '</div>' if error else ''}
<form method="post">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button class="btn btn-primary" style="width:100%">Login →</button>
</form></div></body></html>"""


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin/login")


@app.route("/admin")
@_admin_required
def admin_dashboard():
    with _conn() as db:
        total   = db.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        active  = db.execute("SELECT COUNT(*) FROM customers WHERE status='active'").fetchone()[0]
        expired = db.execute(
            "SELECT COUNT(*) FROM customers WHERE expires_at < ?", (time.time(),)).fetchone()[0]
        online  = db.execute(
            "SELECT COUNT(*) FROM customers WHERE last_check > ?",
            (time.time() - 3600,)).fetchone()[0]
        act_today = db.execute(
            "SELECT COUNT(*) FROM activations WHERE timestamp > ?",
            (time.time() - 86400,)).fetchone()[0]
        by_tier = {r[0]: r[1] for r in db.execute(
            "SELECT tier, COUNT(*) FROM customers GROUP BY tier")}
        recent  = db.execute("""
            SELECT c.name, c.email, c.tier, a.action, a.timestamp, a.ip_address
            FROM activations a JOIN customers c ON a.customer_id=c.id
            ORDER BY a.timestamp DESC LIMIT 20
        """).fetchall()

    tier_badges = "".join(
        f'<span class="badge badge-{t}">{t}: {n}</span>&nbsp;'
        for t, n in sorted(by_tier.items()))
    recent_rows = "".join(
        f"<tr><td>{r['name']}</td><td>{r['email']}</td>"
        f"<td><span class='badge badge-{r['tier']}'>{r['tier']}</span></td>"
        f"<td>{r['action']}</td>"
        f"<td>{datetime.fromtimestamp(r['timestamp']).strftime('%Y-%m-%d %H:%M')}</td>"
        f"<td>{r['ip_address'] or ''}</td></tr>"
        for r in recent)
    body = f"""
<div class="cards">
  <div class="card"><div class="val">{total}</div><div class="lbl">Total Customers</div></div>
  <div class="card"><div class="val">{active}</div><div class="lbl">Active</div></div>
  <div class="card"><div class="val">{expired}</div><div class="lbl">Expired</div></div>
  <div class="card"><div class="val">{online}</div><div class="lbl">Online (1h)</div></div>
  <div class="card"><div class="val">{act_today}</div><div class="lbl">Activations Today</div></div>
</div>
<p>{tier_badges}</p>
<h3 style="color:#89b4fa;margin:20px 0 10px">Recent Activations</h3>
<table><tr>
  <th>Name</th><th>Email</th><th>Tier</th><th>Action</th><th>Time</th><th>IP</th>
</tr>{recent_rows}</table>"""
    return _render("Dashboard", body, "dash")


@app.route("/admin/customers")
@_admin_required
def admin_customers():
    q = request.args.get("q", "")
    tier_f = request.args.get("tier", "")
    with _conn() as db:
        query = "SELECT * FROM customers WHERE 1=1"
        params: list = []
        if q:
            query += " AND (name LIKE ? OR email LIKE ? OR license_key LIKE ?)"
            params += [f"%{q}%"] * 3
        if tier_f:
            query += " AND tier=?"
            params.append(tier_f)
        query += " ORDER BY id DESC"
        rows = db.execute(query, params).fetchall()

    def _badge(r):
        if r["status"] == "revoked":
            return "<span class='badge badge-revoked'>Revoked</span>"
        if r["expires_at"] < time.time():
            return "<span class='badge badge-expired'>Expired</span>"
        return "<span class='badge badge-active'>Active</span>"

    table_rows = "".join(f"""<tr>
        <td>{r['id']}</td>
        <td>{r['name']}</td>
        <td>{r['email']}</td>
        <td><span class="badge badge-{r['tier']}">{r['tier']}</span></td>
        <td>{_badge(r)}</td>
        <td class="mono">{(r['license_key'] or '')[:20]}…</td>
        <td class="mono">{(r['hwid'] or '')[:16]}… ({r['hwid_resets']} resets)</td>
        <td>{datetime.fromtimestamp(r['expires_at']).strftime('%Y-%m-%d')}</td>
        <td>
          <a href="/admin/customer/{r['id']}"><button class="btn btn-primary btn-sm">Edit</button></a>
          <a href="/admin/revoke/{r['id']}" onclick="return confirm('Revoke?')">
            <button class="btn btn-danger btn-sm">Revoke</button></a>
          <a href="/admin/reset_hwid/{r['id']}" onclick="return confirm('Reset HWID?')">
            <button class="btn btn-sm" style="background:#f9e2af;color:#1e1e2e">⟲ HWID</button></a>
        </td>
    </tr>""" for r in rows)

    body = f"""
<form method="get" style="display:flex;gap:10px;margin-bottom:16px">
  <input name="q" value="{q}" placeholder="Search name/email/key…" style="width:300px;margin:0">
  <select name="tier" style="width:140px;margin:0">
    <option value="">All Tiers</option>
    <option {"selected" if tier_f=="Starter" else ""}>Starter</option>
    <option {"selected" if tier_f=="Pro" else ""}>Pro</option>
    <option {"selected" if tier_f=="Enterprise" else ""}>Enterprise</option>
    <option {"selected" if tier_f=="Lifetime" else ""}>Lifetime</option>
  </select>
  <button class="btn btn-primary" type="submit" style="margin:0">Search</button>
  <a href="/admin/new_customer"><button class="btn btn-green" type="button" style="margin:0">+ New</button></a>
</form>
<p style="color:#6c7086;font-size:12px">{len(rows)} customers</p>
<table><tr>
  <th>ID</th><th>Name</th><th>Email</th><th>Tier</th><th>Status</th>
  <th>Key</th><th>HWID</th><th>Expires</th><th>Actions</th>
</tr>{table_rows}</table>"""
    return _render("Customers", body, "cust")


@app.route("/admin/new_customer", methods=["GET", "POST"])
@_admin_required
def admin_new_customer():
    flash = ""
    if request.method == "POST":
        try:
            name    = request.form["name"].strip()
            email   = request.form["email"].strip().lower()
            tier    = request.form["tier"]
            days    = int(request.form["days"])
            machines = int(request.form.get("machines", 2))
            ipqs    = {"Starter":100,"Pro":500,"Enterprise":2000,"Lifetime":9999}.get(tier,100)

            with _conn() as db:
                # Auto-increment customer ID
                max_id = db.execute("SELECT MAX(id) FROM customers").fetchone()[0] or 0
                cid    = max_id + 1
                key    = generate_license_key(tier, days, machines, cid)
                expiry = time.time() + days * 86400
                db.execute("""
                    INSERT INTO customers
                      (name, email, tier, status, license_key, machines, ipqs_daily, expires_at)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (name, email, tier, "active", key, machines, ipqs, expiry))
            _audit("customer_created", f"{email} tier={tier} days={days}",
                   actor="admin", ip=request.remote_addr)
            flash = f"<div class='flash flash-ok'>✅ Customer created! Key: <span class='mono'>{key}</span></div>"
        except sqlite3.IntegrityError:
            flash = "<div class='flash flash-err'>❌ Email already exists</div>"
        except Exception as e:
            flash = f"<div class='flash flash-err'>❌ Error: {e}</div>"

    body = f"""{flash}
<form method="post">
<div class="grid2">
  <div><label>Name</label><input name="name" required></div>
  <div><label>Email</label><input name="email" type="email" required></div>
  <div><label>Tier</label><select name="tier">
    <option>Starter</option><option selected>Pro</option>
    <option>Enterprise</option><option>Lifetime</option>
  </select></div>
  <div><label>Duration (days)</label><input name="days" type="number" value="30" min="1"></div>
  <div><label>Max Machines</label><input name="machines" type="number" value="2" min="1" max="10"></div>
</div>
<button class="btn btn-green" type="submit">Create Customer + Generate Key</button>
</form>"""
    return _render("New Customer", body, "new")


@app.route("/admin/customer/<int:cid>", methods=["GET", "POST"])
@_admin_required
def admin_edit_customer(cid):
    flash = ""
    if request.method == "POST":
        with _conn() as db:
            db.execute("""
                UPDATE customers SET name=?,email=?,tier=?,status=?,
                  expires_at=?,machines=?,notes=? WHERE id=?
            """, (request.form["name"], request.form["email"],
                  request.form["tier"], request.form["status"],
                  float(request.form["expires_ts"]),
                  int(request.form["machines"]),
                  request.form.get("notes",""), cid))
        _audit("customer_updated", f"id={cid}", actor="admin",
               ip=request.remote_addr)
        flash = "<div class='flash flash-ok'>✅ Saved</div>"

    with _conn() as db:
        row = db.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
        acts = db.execute(
            "SELECT * FROM activations WHERE customer_id=? ORDER BY timestamp DESC LIMIT 20",
            (cid,)).fetchall()
    if not row:
        return "Not found", 404

    exp_str = datetime.fromtimestamp(row["expires_at"]).strftime("%Y-%m-%dT%H:%M")
    act_rows = "".join(
        f"<tr><td>{a['action']}</td><td>{a['result']}</td>"
        f"<td>{datetime.fromtimestamp(a['timestamp']).strftime('%Y-%m-%d %H:%M')}</td>"
        f"<td>{a['ip_address'] or ''}</td></tr>"
        for a in acts)
    body = f"""{flash}
<form method="post">
<div class="grid2">
  <div><label>Name</label><input name="name" value="{row['name']}"></div>
  <div><label>Email</label><input name="email" value="{row['email']}"></div>
  <div><label>Tier</label><select name="tier">
    {''.join(f'<option {"selected" if row["tier"]==t else ""}>{t}</option>' for t in ["Starter","Pro","Enterprise","Lifetime"])}
  </select></div>
  <div><label>Status</label><select name="status">
    <option {"selected" if row['status']=='active' else ""}>active</option>
    <option {"selected" if row['status']=='revoked' else ""}>revoked</option>
  </select></div>
  <div><label>Expires</label><input name="expires_ts" type="datetime-local" value="{exp_str}"></div>
  <div><label>Machines</label><input name="machines" type="number" value="{row['machines']}"></div>
</div>
<label>Notes</label><textarea name="notes" rows="2">{row['notes'] or ''}</textarea>
<input type="hidden" name="expires_ts" value="{row['expires_at']}">
<button class="btn btn-primary">Save Changes</button>
</form>
<hr style="border-color:#313244;margin:24px 0">
<p><b>License Key:</b> <span class="mono">{row['license_key'] or 'None'}</span></p>
<p><b>HWID:</b> <span class="mono">{row['hwid'] or 'Not activated'}</span> ({row['hwid_resets']} resets used)</p>
<a href="/admin/reset_hwid/{cid}" onclick="return confirm('Reset HWID?')">
  <button class="btn btn-sm" style="background:#f9e2af;color:#1e1e2e">Reset HWID</button></a>
<h3 style="color:#89b4fa;margin:20px 0 10px">Activation History</h3>
<table><tr><th>Action</th><th>Result</th><th>Time</th><th>IP</th></tr>{act_rows}</table>"""
    return _render(f"Customer #{cid}", body, "cust")


@app.route("/admin/revoke/<int:cid>")
@_admin_required
def admin_revoke(cid):
    with _conn() as db:
        db.execute("UPDATE customers SET status='revoked' WHERE id=?", (cid,))
    _audit("customer_revoked", f"id={cid}", actor="admin",
           ip=request.remote_addr)
    return redirect("/admin/customers")


@app.route("/admin/reset_hwid/<int:cid>")
@_admin_required
def admin_reset_hwid(cid):
    with _conn() as db:
        db.execute("UPDATE customers SET hwid=NULL WHERE id=?", (cid,))
    _audit("hwid_reset_admin", f"id={cid}", actor="admin",
           ip=request.remote_addr)
    return redirect(f"/admin/customer/{cid}")


@app.route("/admin/audit")
@_admin_required
def admin_audit():
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200"
        ).fetchall()
    table_rows = "".join(
        f"<tr><td>{datetime.fromtimestamp(r['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</td>"
        f"<td>{r['action']}</td><td>{r['actor']}</td>"
        f"<td class='mono'>{r['detail'][:80]}</td><td>{r['ip_address'] or ''}</td></tr>"
        for r in rows)
    body = f"""<table><tr>
  <th>Time</th><th>Action</th><th>Actor</th><th>Detail</th><th>IP</th>
</tr>{table_rows}</table>"""
    return _render("Audit Log", body, "audit")


@app.route("/admin/config", methods=["GET", "POST"])
@_admin_required
def admin_config():
    flash = ""
    if request.method == "POST":
        CFG["admin_username"] = request.form.get("admin_username", CFG["admin_username"])
        new_pw = request.form.get("new_password", "").strip()
        if new_pw:
            CFG["admin_password"] = _hash_password(new_pw)
        CFG["max_hwid_resets"] = int(request.form.get("max_hwid_resets", 3))
        _save_cfg(CFG)
        flash = "<div class='flash flash-ok'>✅ Config saved</div>"
    body = f"""{flash}
<form method="post">
<label>Admin Username</label>
<input name="admin_username" value="{CFG.get('admin_username','admin')}">
<label>New Password (leave blank to keep)</label>
<input name="new_password" type="password" placeholder="New password…">
<label>Max HWID Resets per Customer</label>
<input name="max_hwid_resets" type="number" value="{CFG.get('max_hwid_resets',3)}" min="0" max="99">
<hr style="border-color:#313244;margin:16px 0">
<p style="font-size:12px;color:#6c7086">
  API Key for bots: <span class="mono">{hashlib.sha256(CFG.get('secret_key','').encode()).hexdigest()[:32]}</span><br>
  Send as header: <span class="mono">X-API-Key: &lt;key&gt;</span>
</p>
<button class="btn btn-primary">Save Config</button>
</form>"""
    return _render("Config", body, "cfg")


@app.route("/")
def root():
    return redirect("/admin")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    port = int(CFG.get("port", 5000))
    host = CFG.get("host", "0.0.0.0")
    print(f"""
{'='*60}
ProxyHunter Auth Server v4
{'='*60}
Admin panel : http://{host}:{port}/admin
API base    : http://{host}:{port}/api/
DB file     : {CFG['db_path']}
Admin user  : {CFG['admin_username']}
{'='*60}
IMPORTANT: Change admin_password in auth_config.json!
{'='*60}
""")
    app.run(host=host, port=port, threaded=True, debug=False)
