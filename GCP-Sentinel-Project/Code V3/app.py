"""
GCP Sentinel v2 — Cloud Security AI
Full auto-response: IP blocking, server shutdown, IAM revocation, AI remediation
Secure login with session management, rate limiting, audit logging

Run: py app.py
"""

from dotenv import load_dotenv
load_dotenv()

import os
import json
import threading
import time
import random
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit, disconnect
import anthropic

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── Anthropic client ─────────────────────────────────────────────────────────
anthropic_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

# ─── GCP clients (optional) ───────────────────────────────────────────────────
gcp_enabled = False
compute_client = None
firewall_client = None
GCP_PROJECT = os.environ.get("GCP_PROJECT_ID", "")

try:
    from google.cloud import compute_v1, pubsub_v1, logging as gcp_logging
    from google.oauth2 import service_account

    GCP_CREDENTIALS_FILE = os.environ.get("GCP_CREDENTIALS_FILE", "")
    PUBSUB_SUBSCRIPTION = os.environ.get(
        "PUBSUB_SUBSCRIPTION",
        f"projects/{GCP_PROJECT}/subscriptions/sentinel-sub"
    )

    if GCP_CREDENTIALS_FILE and os.path.exists(GCP_CREDENTIALS_FILE) and GCP_PROJECT:
        creds = service_account.Credentials.from_service_account_file(GCP_CREDENTIALS_FILE)
        compute_client   = compute_v1.InstancesClient(credentials=creds)
        firewall_client  = compute_v1.FirewallsClient(credentials=creds)
        pubsub_subscriber = pubsub_v1.SubscriberClient(credentials=creds)
        gcp_enabled = True
        print(f"✅ GCP connected — project: {GCP_PROJECT}")
    else:
        print("⚠️  GCP credentials not found — running in DEMO mode")
except ImportError:
    print("⚠️  google-cloud packages not installed — running in DEMO mode")


# ─── User accounts (hashed passwords) ────────────────────────────────────────
# Default: admin / sentinel123  — change via .env or USERS dict below
# To generate a hash: py -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

USERS = {}

def load_users():
    """Load users from env vars or use defaults."""
    # Format in .env: SENTINEL_USER_admin=hashed_password
    for key, val in os.environ.items():
        if key.startswith("SENTINEL_USER_"):
            username = key[len("SENTINEL_USER_"):].lower()
            USERS[username] = val  # store pre-hashed

    # Default account if none configured
    if not USERS:
        default_pass = os.environ.get("SENTINEL_PASSWORD", "sentinel123")
        USERS["admin"] = hash_password(default_pass)
        print(f"⚠️  Using default credentials: admin / {default_pass}")
        print("   Set SENTINEL_USER_admin=<hashed_pw> in .env to change this")

load_users()

# ─── Rate limiting ────────────────────────────────────────────────────────────
login_attempts = {}  # ip -> [timestamps]
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = login_attempts.get(ip, [])
    # Remove attempts older than lockout window
    attempts = [t for t in attempts if now - t < LOCKOUT_SECONDS]
    login_attempts[ip] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS

def record_login_attempt(ip: str):
    login_attempts.setdefault(ip, []).append(time.time())

def clear_login_attempts(ip: str):
    login_attempts.pop(ip, None)

# ─── Auth helpers ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            if request.is_json:
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def socketio_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            disconnect()
            return
        return f(*args, **kwargs)
    return decorated

# ─── Audit log ────────────────────────────────────────────────────────────────
audit_log = []

def audit(action: str, user: str = "system", ip: str = "—", detail: str = ""):
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "user": user,
        "ip": ip,
        "detail": detail,
    }
    audit_log.insert(0, entry)
    audit_log[:] = audit_log[:500]
    print(f"[AUDIT] {entry['time']} | {user}@{ip} | {action} | {detail}")

# ─── In-memory state ──────────────────────────────────────────────────────────
BLOCKED_IPS   = set()
REVOKED_ACCOUNTS = set()

state = {
    "threats": [],
    "servers": [
        {"id": "instance-api-gw",     "name": "api-gateway-prod",  "zone": "us-central1-a",  "status": "RUNNING",    "ip": "10.0.0.1"},
        {"id": "instance-ml-1",       "name": "ml-inference-1",    "zone": "us-east1-b",     "status": "RUNNING",    "ip": "10.0.0.2"},
        {"id": "instance-db-primary", "name": "db-primary",        "zone": "us-central1-a",  "status": "RUNNING",    "ip": "10.0.0.3"},
        {"id": "instance-web-fe",     "name": "web-frontend",      "zone": "europe-west1-b", "status": "RUNNING",    "ip": "10.0.0.4"},
        {"id": "instance-batch",      "name": "batch-processor",   "zone": "asia-east1-a",   "status": "TERMINATED", "ip": "10.0.0.5"},
        {"id": "instance-auth",       "name": "auth-service",      "zone": "us-central1-c",  "status": "RUNNING",    "ip": "10.0.0.6"},
    ],
    "activity_log": [],
    "blocked_count": 142,
    "auto_shutdown": True,
    "ai_analysis": True,
    "auto_block_ip": True,
    "auto_revoke": True,
    "geo_alert": True,
    "block_brute": True,
    "sensitivity": 4,
    "chat_history": [],
}

KNOWN_DOMAINS = [d.strip() for d in os.environ.get("KNOWN_DOMAINS", "@yourcompany.com").split(",")]

def ts():
    return datetime.now().strftime("%H:%M:%S")

def add_log(message: str, level: str = "info"):
    entry = {"time": ts(), "msg": message, "level": level}
    state["activity_log"].insert(0, entry)
    state["activity_log"] = state["activity_log"][:200]
    socketio.emit("log_update", entry)

def add_threat(threat: dict):
    state["threats"].insert(0, threat)
    state["threats"] = state["threats"][:100]
    socketio.emit("threat_update", threat)
    socketio.emit("stats_update", get_stats())

def get_stats():
    online = sum(1 for s in state["servers"] if s["status"] == "RUNNING")
    return {
        "threats":        len([t for t in state["threats"] if t["severity"] == "CRITICAL"]),
        "suspicious":     len([t for t in state["threats"] if t["severity"] in ("CRITICAL", "WARNING")]),
        "servers_online": online,
        "servers_total":  len(state["servers"]),
        "blocked":        state["blocked_count"],
        "blocked_ips":    len(BLOCKED_IPS),
        "revoked_accounts": len(REVOKED_ACCOUNTS),
        "gcp_enabled":    gcp_enabled,
    }


# ─── GCP: Firewall / IAM actions ─────────────────────────────────────────────

def block_ip(ip: str):
    """Create a GCP firewall DENY rule for this IP."""
    if ip in BLOCKED_IPS:
        return False, f"{ip} already blocked"

    rule_name = f"sentinel-block-{ip.replace('.', '-')}"

    if gcp_enabled:
        try:
            fw = compute_v1.Firewall()
            fw.name = rule_name
            fw.network = f"projects/{GCP_PROJECT}/global/networks/default"
            fw.direction = "INGRESS"
            fw.priority = 900
            fw.denied = [compute_v1.Denied(I_p_protocol="all")]
            fw.source_ranges = [f"{ip}/32"]
            fw.description = "Auto-blocked by GCP Sentinel"
            firewall_client.insert(project=GCP_PROJECT, firewall_resource=fw)
            BLOCKED_IPS.add(ip)
            return True, f"GCP firewall rule created: {rule_name}"
        except Exception as e:
            return False, str(e)
    else:
        BLOCKED_IPS.add(ip)
        return True, f"[DEMO] Firewall rule: block {ip}/32"


def revoke_account(email: str):
    """Strip all IAM roles from a suspicious service account."""
    if email in REVOKED_ACCOUNTS:
        return False, f"{email} already revoked"

    if gcp_enabled:
        try:
            import subprocess
            for role in ["roles/editor", "roles/viewer", "roles/owner"]:
                subprocess.run([
                    "gcloud", "projects", "remove-iam-policy-binding", GCP_PROJECT,
                    "--member", f"serviceAccount:{email}",
                    "--role", role, "--quiet"
                ], capture_output=True)
            REVOKED_ACCOUNTS.add(email)
            return True, f"IAM bindings removed for {email}"
        except Exception as e:
            return False, str(e)
    else:
        REVOKED_ACCOUNTS.add(email)
        return True, f"[DEMO] IAM revoked for {email}"


def shutdown_instance(instance_id: str, reason: str = "security"):
    server = next((s for s in state["servers"] if s["id"] == instance_id), None)
    if not server or server["status"] == "TERMINATED":
        return False, "Server not found or already stopped"

    if gcp_enabled:
        try:
            op = compute_client.stop(project=GCP_PROJECT, zone=server["zone"], instance=server["name"])
            op.result(timeout=60)
        except Exception as e:
            return False, str(e)

    server["status"] = "TERMINATED"
    socketio.emit("server_update", server)
    socketio.emit("stats_update", get_stats())
    msg = f"{'🔴 GCP' if gcp_enabled else '🔴 [DEMO]'} SHUTDOWN: {server['name']} — {reason}"
    add_log(msg, "danger")
    return True, msg


def restore_instance(instance_id: str):
    server = next((s for s in state["servers"] if s["id"] == instance_id), None)
    if not server:
        return False, "Server not found"

    if gcp_enabled:
        try:
            op = compute_client.start(project=GCP_PROJECT, zone=server["zone"], instance=server["name"])
            op.result(timeout=60)
        except Exception as e:
            return False, str(e)

    server["status"] = "RUNNING"
    socketio.emit("server_update", server)
    socketio.emit("stats_update", get_stats())
    add_log(f"✅ RESTORED: {server['name']}", "ok")
    return True, f"Restored {server['name']}"


# ─── Auto-response engine ─────────────────────────────────────────────────────

def auto_respond_to_threat(threat: dict):
    """
    Full automated response:
    1. Block IP via firewall
    2. Revoke account IAM
    3. Shutdown affected server
    4. Ask Claude for additional remediation steps
    """
    actions = []

    # 1. Block the IP
    if state.get("auto_block_ip") and threat.get("ip"):
        ok, msg = block_ip(threat["ip"])
        if ok:
            actions.append(f"🚫 Blocked IP {threat['ip']}")
            audit("BLOCK_IP", detail=f"{threat['ip']} — threat {threat['id']}")

    # 2. Revoke the account
    if state.get("auto_revoke") and threat.get("account"):
        ok, msg = revoke_account(threat["account"])
        if ok:
            actions.append(f"🔐 Revoked {threat['account']}")
            audit("REVOKE_ACCOUNT", detail=threat["account"])

    # 3. Shutdown affected server
    if state["auto_shutdown"] and threat.get("server_id"):
        ok, msg = shutdown_instance(threat["server_id"], reason=f"auto-response to {threat['ip']}")
        if ok:
            actions.append(f"🔴 Shut down {threat['instance']}")
            audit("SHUTDOWN_SERVER", detail=threat["instance"])

    state["blocked_count"] += 1

    # Push actions to dashboard
    socketio.emit("auto_response", {
        "threat_id": threat["id"],
        "actions": actions,
        "time": ts(),
    })

    if actions:
        add_log(f"⚡ AUTO-RESPONSE: {' | '.join(actions)}", "ok")

    # 4. AI remediation advice
    if state["ai_analysis"] and os.environ.get("ANTHROPIC_API_KEY"):
        threading.Thread(target=ai_auto_fix, args=(threat, actions), daemon=True).start()

    socketio.emit("stats_update", get_stats())


def ai_auto_fix(threat: dict, actions_taken: list):
    """Ask Claude for additional remediation and push to dashboard."""
    try:
        actions_str = "\n".join(actions_taken) if actions_taken else "None taken yet"
        msg = (
            f"AUTOMATED SECURITY RESPONSE EXECUTED:\n"
            f"Threat: {threat['desc']}\n"
            f"IP: {threat['ip']} (GEO: {threat['country']})\n"
            f"Account: {threat.get('account', 'unknown')}\n"
            f"Server: {threat.get('instance', 'N/A')}\n\n"
            f"Actions already taken automatically:\n{actions_str}\n\n"
            f"What 3 additional GCP hardening steps should I take RIGHT NOW? "
            f"Be specific, brief, actionable. Reference exact GCP services."
        )
        resp = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=400,
            system=build_system_prompt(),
            messages=[{"role": "user", "content": msg}],
        )
        advice = resp.content[0].text
        summary = "✅ AUTO-RESPONSE COMPLETE\n\nActions taken:\n" + "\n".join(actions_taken)
        summary += f"\n\nAI recommends:\n{advice}"

        socketio.emit("ai_threat_analysis", {
            "threat_id": threat["id"],
            "analysis": summary,
            "time": ts(),
        })
        add_log("🤖 AI remediation advice generated", "ok")
    except Exception as e:
        print(f"AI auto-fix error: {e}")


# ─── AI chat system prompt ────────────────────────────────────────────────────

def build_system_prompt():
    online  = [s["name"] for s in state["servers"] if s["status"] == "RUNNING"]
    offline = [s["name"] for s in state["servers"] if s["status"] != "RUNNING"]
    recent  = state["threats"][:5]
    return f"""You are GCP Sentinel, an elite cloud security AI for Google Cloud Platform.

Environment:
- Mode: {"LIVE GCP" if gcp_enabled else "DEMO"}
- Project: {GCP_PROJECT or "demo-project"}
- Online servers: {', '.join(online) or 'none'}
- Shutdown servers: {', '.join(offline) or 'none'}
- Blocked IPs: {len(BLOCKED_IPS)} ({', '.join(list(BLOCKED_IPS)[:3])}{'...' if len(BLOCKED_IPS) > 3 else ''})
- Revoked accounts: {len(REVOKED_ACCOUNTS)}
- Blocked attempts today: {state['blocked_count']}
- Auto-shutdown: {state['auto_shutdown']} | Auto-block IP: {state.get('auto_block_ip')} | Auto-revoke: {state.get('auto_revoke')}
- Recent threats:
{chr(10).join(f"  [{t['severity']}] {t['desc']} — IP {t['ip']} ({t['country']})" for t in recent)}

Known safe domains: {', '.join(KNOWN_DOMAINS)}

Your role:
1. Analyze threats with precision and urgency
2. Recommend specific GCP actions (IAM, Cloud Armor, VPC SC, firewall rules, Security Command Center)
3. Advise on server shutdowns and account revocations
4. Provide incident response and post-incident hardening steps
5. Be concise (3-5 sentences), direct, and technical
6. Use 🔴 critical / 🟡 warning / 🟢 safe indicators"""


# ─── Demo: random threat generator ───────────────────────────────────────────

FAKE_ACCOUNTS  = [
    "sa-9x2k@external-proj.iam.gserviceaccount.com",
    "root@compromised-host",
    "admin-bot@foreign.iam",
    "crawler@unknown-org.com",
    "service@malicious-app.iam.gserviceaccount.com",
]
FAKE_METHODS   = ["compute.instances.get", "storage.buckets.list", "iam.serviceAccounts.actAs",
                   "compute.instances.setMetadata", "cloudsql.instances.login"]
FAKE_COUNTRIES = ["RU", "CN", "KP", "IR", "BR", "NG"]


def demo_threat_generator():
    time.sleep(6)
    while True:
        time.sleep(random.randint(25, 70))
        if random.random() < 0.25:
            continue

        running  = [s for s in state["servers"] if s["status"] == "RUNNING"]
        target   = random.choice(running) if running else None
        ip       = f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        acct     = random.choice(FAKE_ACCOUNTS)
        method   = random.choice(FAKE_METHODS)
        country  = random.choice(FAKE_COUNTRIES)
        severity = random.choice(["CRITICAL", "CRITICAL", "WARNING"])

        threat = {
            "id":        f"t-{int(time.time()*1000)}",
            "severity":  severity,
            "desc":      f"Unknown account '{acct}' attempted '{method}'" + (f" on {target['name']}" if target else ""),
            "time":      ts(),
            "ip":        ip,
            "country":   country,
            "account":   acct,
            "server_id": target["id"] if target else None,
            "instance":  target["name"] if target else None,
            "source":    "DEMO",
        }
        add_threat(threat)
        add_log(f"🚨 [DEMO] Threat from {ip} ({country}): {acct}", "danger")

        if severity == "CRITICAL":
            threading.Thread(target=auto_respond_to_threat, args=(threat,), daemon=True).start()


# ─── Routes: auth ─────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET"])
def login_page():
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    ip       = request.remote_addr
    data     = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if is_rate_limited(ip):
        audit("LOGIN_BLOCKED", user=username, ip=ip, detail="rate limited")
        return jsonify({"ok": False, "error": "Too many attempts. Try again in 5 minutes."}), 429

    stored_hash = USERS.get(username)
    if not stored_hash or stored_hash != hash_password(password):
        record_login_attempt(ip)
        remaining = MAX_LOGIN_ATTEMPTS - len(login_attempts.get(ip, []))
        audit("LOGIN_FAILED", user=username, ip=ip)
        return jsonify({"ok": False, "error": f"Invalid credentials. {max(0,remaining)} attempts remaining."}), 401

    clear_login_attempts(ip)
    session.permanent = True
    session["authenticated"] = True
    session["username"]      = username
    session["login_time"]    = datetime.now().isoformat()
    audit("LOGIN_SUCCESS", user=username, ip=ip)
    add_log(f"🔓 Login: {username} from {ip}", "ok")
    return jsonify({"ok": True})


@app.route("/logout")
def logout():
    user = session.get("username", "unknown")
    ip   = request.remote_addr
    session.clear()
    audit("LOGOUT", user=user, ip=ip)
    add_log(f"🔒 Logout: {user}", "info")
    return redirect(url_for("login_page"))


# ─── Routes: dashboard ────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("dashboard.html", username=session.get("username", "admin"))


@app.route("/api/state")
@login_required
def api_state():
    return jsonify({
        "servers":      state["servers"],
        "threats":      state["threats"][:20],
        "activity_log": state["activity_log"][:30],
        "stats":        get_stats(),
        "blocked_ips":  list(BLOCKED_IPS),
        "revoked_accounts": list(REVOKED_ACCOUNTS),
        "settings": {
            "auto_shutdown":  state["auto_shutdown"],
            "ai_analysis":    state["ai_analysis"],
            "auto_block_ip":  state["auto_block_ip"],
            "auto_revoke":    state["auto_revoke"],
            "geo_alert":      state["geo_alert"],
            "block_brute":    state["block_brute"],
            "sensitivity":    state["sensitivity"],
        },
    })


@app.route("/api/server/<instance_id>/shutdown", methods=["POST"])
@login_required
def api_shutdown(instance_id):
    user = session.get("username")
    ok, msg = shutdown_instance(instance_id, reason=f"manual shutdown by {user}")
    audit("MANUAL_SHUTDOWN", user=user, ip=request.remote_addr, detail=instance_id)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/server/<instance_id>/restore", methods=["POST"])
@login_required
def api_restore(instance_id):
    user = session.get("username")
    ok, msg = restore_instance(instance_id)
    audit("MANUAL_RESTORE", user=user, ip=request.remote_addr, detail=instance_id)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/lockdown", methods=["POST"])
@login_required
def api_lockdown():
    user = session.get("username")
    results = []
    for s in state["servers"]:
        if s["status"] == "RUNNING":
            ok, msg = shutdown_instance(s["id"], reason="emergency lockdown")
            results.append(msg)
    audit("EMERGENCY_LOCKDOWN", user=user, ip=request.remote_addr)
    add_log("🚨 EMERGENCY LOCKDOWN — ALL SERVERS OFFLINE", "danger")
    socketio.emit("lockdown", {"time": ts()})
    return jsonify({"ok": True, "results": results})


@app.route("/api/block-ip", methods=["POST"])
@login_required
def api_block_ip():
    ip   = (request.get_json() or {}).get("ip", "")
    user = session.get("username")
    ok, msg = block_ip(ip)
    audit("MANUAL_BLOCK_IP", user=user, ip=request.remote_addr, detail=ip)
    socketio.emit("stats_update", get_stats())
    return jsonify({"ok": ok, "msg": msg})


@app.route("/api/settings", methods=["POST"])
@login_required
def api_settings():
    data = request.get_json() or {}
    for key in ("auto_shutdown", "ai_analysis", "auto_block_ip", "auto_revoke",
                "geo_alert", "block_brute", "sensitivity"):
        if key in data:
            state[key] = data[key]
    audit("SETTINGS_CHANGE", user=session.get("username"), detail=str(data))
    return jsonify({"ok": True})


@app.route("/api/simulate", methods=["POST"])
@login_required
def api_simulate():
    running = [s for s in state["servers"] if s["status"] == "RUNNING"]
    target  = random.choice(running) if running else None
    ip      = f"{random.randint(10,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    acct    = random.choice(FAKE_ACCOUNTS)
    country = random.choice(FAKE_COUNTRIES)

    threat = {
        "id":        f"t-{int(time.time()*1000)}",
        "severity":  "CRITICAL",
        "desc":      f"Unknown account '{acct}' attempted SSH login" + (f" on {target['name']}" if target else ""),
        "time":      ts(),
        "ip":        ip,
        "country":   country,
        "account":   acct,
        "server_id": target["id"] if target else None,
        "instance":  target["name"] if target else None,
        "source":    "SIMULATED",
    }
    add_threat(threat)
    add_log(f"🧪 SIMULATED ATTACK: {acct} from {ip}", "warn")
    audit("SIMULATE_ATTACK", user=session.get("username"), detail=ip)
    threading.Thread(target=auto_respond_to_threat, args=(threat,), daemon=True).start()
    return jsonify({"ok": True, "threat": threat})


@app.route("/api/audit-log")
@login_required
def api_audit_log():
    return jsonify(audit_log[:100])


# ─── Socket.IO: chat (auth required) ─────────────────────────────────────────

@socketio.on("chat_message")
@socketio_login_required
def handle_chat(data):
    user_msg = data.get("message", "").strip()
    if not user_msg:
        return

    add_log(f"💬 {session.get('username')}: {user_msg[:60]}", "info")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        emit("chat_done", {"full": "⚠️ No ANTHROPIC_API_KEY set in .env"})
        return

    state["chat_history"].append({"role": "user", "content": user_msg})
    state["chat_history"] = state["chat_history"][-20:]

    def _stream():
        try:
            with anthropic_client.messages.stream(
                model="claude-sonnet-4-20250514",
                max_tokens=600,
                system=build_system_prompt(),
                messages=state["chat_history"],
            ) as stream:
                full = ""
                for text in stream.text_stream:
                    full += text
                    socketio.emit("chat_chunk", {"chunk": text})
                socketio.emit("chat_done", {"full": full})
                state["chat_history"].append({"role": "assistant", "content": full})
        except Exception as e:
            socketio.emit("chat_done", {"full": f"⚠️ AI error: {e}"})

    threading.Thread(target=_stream, daemon=True).start()


# ─── Startup ──────────────────────────────────────────────────────────────────

def startup():
    add_log("🟢 GCP Sentinel v2 initialized", "ok")
    add_log(f"🌐 Mode: {'LIVE GCP' if gcp_enabled else 'DEMO'}", "info")
    add_log(f"🤖 AI: {'Claude connected' if os.environ.get('ANTHROPIC_API_KEY') else 'No API key'}", "info")
    add_log(f"🔒 Auth: {len(USERS)} user(s) configured", "info")

    # Seed demo threats
    for i, (acct, ip, country, sev) in enumerate([
        ("sa-9x2k@external.iam",  "185.220.101.47", "RU", "CRITICAL"),
        ("admin-bot@foreign.iam", "45.33.32.156",   "CN", "CRITICAL"),
        ("crawler@unknown.com",   "104.21.0.88",    "US", "WARNING"),
    ]):
        state["threats"].append({
            "id":        f"seed-{i}",
            "severity":  sev,
            "desc":      f"Unknown account '{acct}' attempted access",
            "time":      (datetime.now() - timedelta(minutes=5*(i+1))).strftime("%H:%M:%S"),
            "ip":        ip,
            "country":   country,
            "account":   acct,
            "server_id": state["servers"][i]["id"],
            "instance":  state["servers"][i]["name"],
            "source":    "SEED",
        })

    if not gcp_enabled:
        threading.Thread(target=demo_threat_generator, daemon=True).start()


if __name__ == "__main__":
    startup()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n🚀 GCP Sentinel running → http://localhost:{port}")
    print(f"🔑 Login: admin / {os.environ.get('SENTINEL_PASSWORD', 'sentinel123')}\n")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
