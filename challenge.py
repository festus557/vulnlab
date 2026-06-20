# ============================================================
# HTB-Style Challenge: "Corporate Breach"
# A multi-step attack chain leading to RCE
# ============================================================
#
# ATTACK CHAIN OVERVIEW:
# ======================
#
# Step 1 - RECONNAISSANCE (Info Leak)
#   The /debug endpoint exposes internal API routes and service info.
#   No authentication required. Reveals hidden endpoints.
#
# Step 2 - IDOR (Access Other User Data)
#   /api/v2/users/<id> leaks password hints and internal notes.
#   User ID 3 (dev_ops) has a weak password hint.
#
# Step 3 - SQL INJECTION (Auth Bypass)
#   /api/v2/login is vulnerable to SQLi. Use dev_ops credentials
#   found in Step 2 to authenticate.
#
# Step 4 - STORED XSS (Cookie Theft)
#   /api/v2/profile allows updating bio field. No sanitization.
#   Inject XSS payload to steal cookies of anyone who views profile.
#   The admin bot visits profiles every few minutes.
#
# Step 5 - CSRF (Privilege Escalation)
#   Admin panel at /admin has a config update form with no CSRF token.
#   Use the stolen admin cookie to access /admin/api/config and
#   enable the "developer_tools" feature.
#
# Step 6 - SSRF (Internal Network Scan)
#   The admin panel has a "Health Check" feature at /admin/api/health
#   that fetches a URL. Use it to scan internal services.
#   Discover internal dev server at http://127.0.0.1:8080
#
# Step 7 - COMMAND INJECTION (Initial Foothold)
#   The dev server at /dev/ping has a command injection vulnerability.
#   Chain with SSRF from admin panel to reach it.
#
# Step 8 - RCE (Full Compromise)
#   Use command injection through SSRF to get a reverse shell.
#   Read the final flag from /root/flag.txt
#
# ============================================================

import os
import sqlite3
import subprocess
import hashlib
import json
import base64
import pickle
import socket
import threading
import time
import re
from functools import wraps
from io import StringIO
from flask import (Blueprint, request, render_template_string, redirect,
                   url_for, session, flash, make_response, jsonify,
                   send_from_directory, abort, g, current_app)
from werkzeug.utils import secure_filename

htb = Blueprint('htb', __name__)

# Color scheme
COLORS = {
    'bg': '#0a0e17',
    'card': '#111827',
    'border': '#1f2937',
    'text': '#9ca3af',
    'blue': '#3b82f6',
    'green': '#10b981',
    'red': '#ef4444',
    'yellow': '#f59e0b',
    'purple': '#8b5cf6',
    'cyan': '#06b6d4',
}

BASE_TPL = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CorpSec Internal Portal - {{ title }}</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Courier New', monospace; background:{{ colors.bg }}; color:{{ colors.text }}; min-height:100vh; }
.navbar { background:{{ colors.card }}; padding:12px 24px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid {{ colors.border }}; }
.navbar h1 { color:{{ colors.red }}; font-size:20px; letter-spacing:2px; }
.navbar h1 span { color:{{ colors.green }}; }
.nav-links { display:flex; gap:16px; flex-wrap:wrap; }
.nav-links a { color:{{ colors.text }}; text-decoration:none; font-size:12px; padding:4px 8px; border:1px solid {{ colors.border }}; border-radius:4px; transition:all .2s; }
.nav-links a:hover { color:{{ colors.green }}; border-color:{{ colors.green }}; }
.nav-links a.active { color:{{ colors.green }}; border-color:{{ colors.green }}; background:rgba(16,185,129,0.1); }
.container { max-width:1100px; margin:24px auto; padding:0 20px; }
.card { background:{{ colors.card }}; border:1px solid {{ colors.border }}; border-radius:6px; padding:20px; margin-bottom:16px; }
.card h2 { color:{{ colors.cyan }}; margin-bottom:8px; font-size:16px; }
.card h3 { color:{{ colors.yellow }}; margin:12px 0 6px; font-size:14px; }
.card p, .card li { color:{{ colors.text }}; font-size:13px; line-height:1.6; }
.card ul { margin-left:20px; }
input[type="text"], input[type="password"], input[type="email"], input[type="url"],
textarea, select { width:100%; padding:8px 12px; background:{{ colors.bg }}; border:1px solid {{ colors.border }}; border-radius:4px; color:{{ colors.text }}; font-family:'Courier New',monospace; font-size:13px; margin-bottom:8px; }
input:focus, textarea:focus { outline:none; border-color:{{ colors.blue }}; }
textarea { min-height:80px; resize:vertical; }
.btn { display:inline-block; padding:8px 16px; background:transparent; color:{{ colors.green }}; border:1px solid {{ colors.green }}; border-radius:4px; cursor:pointer; text-decoration:none; font-family:'Courier New',monospace; font-size:12px; margin:4px 4px 4px 0; transition:all .2s; }
.btn:hover { background:rgba(16,185,129,0.15); }
.btn-red { color:{{ colors.red }}; border-color:{{ colors.red }}; }
.btn-red:hover { background:rgba(239,68,68,0.15); }
.btn-blue { color:{{ colors.blue }}; border-color:{{ colors.blue }}; }
.btn-blue:hover { background:rgba(59,130,246,0.15); }
.result { background:{{ colors.bg }}; border:1px solid {{ colors.border }}; border-radius:4px; padding:12px; margin-top:12px; white-space:pre-wrap; font-size:12px; font-family:'Courier New',monospace; max-height:400px; overflow:auto; }
.result.ok { border-color:{{ colors.green }}; }
.result.error { border-color:{{ colors.red }}; }
.result.warn { border-color:{{ colors.yellow }}; }
.hint { background:rgba(245,158,11,0.08); border-left:3px solid {{ colors.yellow }}; padding:8px 12px; margin:8px 0; font-size:12px; }
.step { display:flex; gap:12px; align-items:flex-start; margin-bottom:12px; padding:12px; background:{{ colors.bg }}; border:1px solid {{ colors.border }}; border-radius:4px; }
.step-num { background:{{ colors.red }}; color:white; width:28px; height:28px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:bold; flex-shrink:0; margin-top:2px; }
.step.done .step-num { background:{{ colors.green }}; }
.step-content { flex:1; }
.step-content h4 { color:{{ colors.cyan }}; font-size:13px; margin-bottom:4px; }
.step-content p { font-size:12px; color:{{ colors.text }}; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:bold; }
.badge-easy { background:rgba(16,185,129,0.2); color:{{ colors.green }}; }
.badge-med { background:rgba(245,158,11,0.2); color:{{ colors.yellow }}; }
.badge-hard { background:rgba(239,68,68,0.2); color:{{ colors.red }}; }
.badge-insane { background:rgba(139,92,246,0.2); color:{{ colors.purple }}; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th, td { padding:8px 10px; text-align:left; border-bottom:1px solid {{ colors.border }}; }
th { color:{{ colors.cyan }}; }
.flash { padding:8px 14px; border-radius:4px; margin-bottom:12px; font-size:12px; }
.flash-ok { background:rgba(16,185,129,0.15); border:1px solid {{ colors.green }}; color:{{ colors.green }}; }
.flash-err { background:rgba(239,68,68,0.15); border:1px solid {{ colors.red }}; color:{{ colors.red }}; }
.flash-info { background:rgba(59,130,246,0.15); border:1px solid {{ colors.blue }}; color:{{ colors.blue }}; }
label { display:block; margin-bottom:4px; color:{{ colors.text }}; font-size:12px; }
code { background:{{ colors.bg }}; padding:1px 5px; border-radius:3px; font-size:12px; color:{{ colors.green }}; }
.cookie-banner { position:fixed; bottom:0; left:0; right:0; background:{{ colors.card }}; border-top:1px solid {{ colors.red }}; padding:10px 20px; font-size:11px; color:{{ colors.text }}; z-index:100; }
</style>
</head>
<body>
<nav class="navbar">
  <h1>&gt;_<span>Corp</span>Sec</h1>
  <div class="nav-links">
    <a href="/htb" class="{{ 'active' if active_page == 'htb_home' else '' }}">Challenge</a>
    <a href="/htb/debug" class="{{ 'active' if active_page == 'debug' else '' }}">Debug</a>
    <a href="/htb/login" class="{{ 'active' if active_page == 'login' else '' }}">Login</a>
    <a href="/htb/profile" class="{{ 'active' if active_page == 'profile' else '' }}">Profile</a>
    <a href="/htb/users" class="{{ 'active' if active_page == 'users' else '' }}">Users</a>
    <a href="/htb/admin" class="{{ 'active' if active_page == 'admin' else '' }}">Admin</a>
    <a href="/htb/dev" class="{{ 'active' if active_page == 'dev' else '' }}">Dev Tools</a>
    <a href="/htb/flag" class="{{ 'active' if active_page == 'flag' else '' }}">Get Flag</a>
  </div>
</nav>
<div class="container">
{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}
{% for cat, msg in messages %}
<div class="flash flash-{{ cat }}">{{ msg }}</div>
{% endfor %}
{% endif %}
{% endwith %}
{{ content | safe }}
</div>
</body>
</html>
'''

# ============================================================
# Database
# ============================================================

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(current_app.config['HTB_DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@htb.teardown_app_request
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(current_app.config['HTB_DATABASE'])
    conn.row_factory = sqlite3.Row
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS htb_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT,
            bio TEXT DEFAULT '',
            password_hint TEXT DEFAULT '',
            internal_notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS htb_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES htb_users(id)
        );
        CREATE TABLE IF NOT EXISTS htb_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_by TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS htb_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            detail TEXT,
            ip TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS htb_flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flag_name TEXT NOT NULL,
            flag_value TEXT NOT NULL,
            difficulty TEXT DEFAULT 'insane'
        );
    ''')

    users = [
        ('admin', hashlib.sha256(b'SuperSecretP@ssw0rd!2024#Admin').hexdigest(),
         'admin', 'admin@corpsec.internal',
         'System Administrator', 'Starts with Super...', 'Full system access. Flag location: /root/flag.txt'),
        ('dev_ops', hashlib.sha256(b'Dev0ps2024!').hexdigest(),
         'developer', 'devops@corpsec.internal',
         'DevOps Engineer', 'Dev0ps + year + !', 'Has access to dev tools panel. Internal IP: 127.0.0.1:8080'),
        ('john_smith', hashlib.sha256(b'John123!').hexdigest(),
         'user', 'john@corpsec.internal',
         'Software Developer', 'Name + numbers + !', 'Regular user. No special access.'),
        ('jane_doe', hashlib.sha256(b'Jane2024!').hexdigest(),
         'user', 'jane@corpsec.internal',
         'QA Tester', 'Name + year + !', 'Regular user. Reviews profiles for quality.'),
        ('security_bot', hashlib.sha256(b'B0t_S3cur1ty!').hexdigest(),
         'bot', 'bot@corpsec.internal',
         'Automated Security Scanner', 'N/A - Service account', 'Visits all profiles every 2 minutes to check for XSS. Has admin cookie.'),
    ]
    for u in users:
        try:
            conn.execute('INSERT INTO htb_users (username,password,role,email,bio,password_hint,internal_notes) VALUES (?,?,?,?,?,?,?)', u)
        except:
            pass

    configs = [
        ('developer_tools', 'disabled', 'admin'),
        ('debug_mode', 'disabled', 'admin'),
        ('profile_review', 'enabled', 'admin'),
        ('max_login_attempts', '5', 'admin'),
        ('internal_api_key', 'sk-internal-8f7g6h5j4k3l2m1n0p9q8r7s6t5u4v3w', 'admin'),
        ('flag', 'flag{htb_ch41n_r34l_w0rld_pwn3d_g00d_j0b}', 'admin'),
    ]
    for c in configs:
        try:
            conn.execute('INSERT INTO htb_config (key, value, updated_by) VALUES (?,?,?)', c)
        except:
            pass

    flags = [
        ('recon', 'flag{r3c0n_1s_k3y_t0_3v3ryth1ng}', 'easy'),
        ('idor', 'flag{1d0r_l34ks_4ll_th3_th1ngs}', 'easy'),
        ('sqli', 'flag{sqli_byp4ss_m4st3r}', 'medium'),
        ('xss', 'flag{st0r3d_xss_c00k13_th13f}', 'medium'),
        ('csrf', 'flag{csrf_pr1v1l3g3_3sc4l4t10n}', 'medium'),
        ('ssrf', 'flag{ssrf_1nt3rn4l_n3tw0rk_sc4n}', 'hard'),
        ('rce', 'flag{htb_ch41n_r34l_w0rld_pwn3d_g00d_j0b}', 'insane'),
    ]
    for f in flags:
        try:
            conn.execute('INSERT INTO htb_flags (flag_name, flag_value, difficulty) VALUES (?,?,?)', f)
        except:
            pass

    conn.commit()
    conn.close()

# ============================================================
# Helpers
# ============================================================

def get_config(key):
    conn = sqlite3.connect(current_app.config['HTB_DATABASE'])
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT value FROM htb_config WHERE key=?', (key,)).fetchone()
    conn.close()
    return row['value'] if row else None

def set_config(key, value, updated_by):
    conn = sqlite3.connect(current_app.config['HTB_DATABASE'])
    conn.execute('INSERT OR REPLACE INTO htb_config (key,value,updated_by,updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP)',
                 (key, value, updated_by))
    conn.commit()
    conn.close()

def log_action(action, detail=''):
    try:
        conn = sqlite3.connect(current_app.config['HTB_DATABASE'])
        conn.execute('INSERT INTO htb_audit_log (action, detail, ip, user_agent) VALUES (?,?,?,?)',
                     (action, detail, request.remote_addr, request.headers.get('User-Agent', '')[:200]))
        conn.commit()
        conn.close()
    except:
        pass

def get_user_by_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        'SELECT u.* FROM htb_users u JOIN htb_sessions s ON s.user_id=u.id WHERE s.token=?', (token,)
    ).fetchone()
    conn.close()
    return row

# ============================================================
# Step 1: RECONNAISSANCE - Info Leak via Debug Endpoint
# ============================================================

DEBUG_CONTENT = '''
<div class="card">
<h2>&gt;_ Debug Information</h2>
<p>System debug information for authorized personnel only.</p>
<pre class="result">{{ debug_info }}</pre>
</div>
<div class="card">
<h2>&gt;_ System Status</h2>
<table>
<tr><th>Service</th><th>Status</th><th>Endpoint</th></tr>
<tr><td>Main Application</td><td><span style="color:{{ colors.green }}">ONLINE</span></td><td>/</td></tr>
<tr><td>User API v2</td><td><span style="color:{{ colors.green }}">ONLINE</span></td><td>/api/v2/*</td></tr>
<tr><td>Admin Panel</td><td><span style="color:{{ colors.green }}">ONLINE</span></td><td>/admin/*</td></tr>
<tr><td>Dev Tools</td><td><span style="color:{{ colors.yellow }}">{{ dev_status }}</span></td><td>/dev/*</td></tr>
<tr><td>Health Check</td><td><span style="color:{{ colors.green }}">ONLINE</span></td><td>/admin/api/health</td></tr>
</table>
</div>
<div class="card">
<h2>&gt;_ API Routes (Internal)</h2>
<pre class="result">{{ api_routes }}</pre>
</div>
'''

@htb.route('/debug')
def htb_debug():
    # VULNERABLE: Exposes internal API structure, config hints, and service info
    # No authentication check - should be protected
    dev_status = "ENABLED" if get_config('developer_tools') == 'enabled' else "DISABLED"

    debug_info = f"""
=== CorpSec Internal Debug ===
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
Server: corpsec-internal-v2.4.1
Environment: production

[WARNING] Debug mode should be disabled in production!
[WARNING] This endpoint exposes sensitive internal information.

Internal Services:
  - Main App: http://127.0.0.1:5000
  - Dev Server: http://127.0.0.1:8080 (status: {dev_status.lower()})
  - Internal API: http://127.0.0.1:5000/api/v2/

Developer Tools: {dev_status}
Internal API Key: {get_config('internal_api_key')[:12]}...{get_config('internal_api_key')[-8:]}

Notes:
  - Admin panel requires admin cookie
  - Dev tools require developer_tools config = enabled
  - User profiles are reviewed by security_bot (admin access)
"""
    api_routes = """
GET  /api/v2/users/<id>       - Get user profile (IDOR vulnerable)
POST /api/v2/login             - User login (SQLi vulnerable)
POST /api/v2/profile           - Update profile (XSS vulnerable)
GET  /api/v2/flag              - Get flag (requires RCE)
GET  /admin/api/health         - Health check (SSRF vulnerable)
POST /admin/api/config         - Update config (CSRF vulnerable)
GET  /dev/ping                 - Ping tool (Command Injection)
"""
    log_action('debug_access', f'Accessed from {request.remote_addr}')
    return render_template_string(BASE_TPL, title='Debug', active_page='debug',
        content=render_template_string(DEBUG_CONTENT, debug_info=debug_info, api_routes=api_routes,
                                       dev_status=dev_status, colors=COLORS),
        colors=COLORS)

# ============================================================
# Step 2: IDOR - Access Other Users' Data
# ============================================================

@htb.route('/users')
@htb.route('/users/<int:user_id>')
def htb_users(user_id=None):
    conn = get_db()
    if user_id:
        # VULNERABLE: No authorization check - any user can view any profile
        user = conn.execute('SELECT id, username, role, email, bio, password_hint, internal_notes FROM htb_users WHERE id=?', (user_id,)).fetchone()
        if user:
            content = f'''
<div class="card">
<h2>&gt;_ User Profile: {user['username']}</h2>
<table>
<tr><td>ID</td><td>{user['id']}</td></tr>
<tr><td>Username</td><td>{user['username']}</td></tr>
<tr><td>Role</td><td>{user['role']}</td></tr>
<tr><td>Email</td><td>{user['email']}</td></tr>
<tr><td>Bio</td><td>{user['bio']}</td></tr>
<tr><td>Password Hint</td><td><span style="color:{COLORS['yellow']}">{user['password_hint']}</span></td></tr>
<tr><td>Internal Notes</td><td><span style="color:{COLORS['red']}">{user['internal_notes']}</span></td></tr>
</table>
</div>'''
            log_action('idor_access', f'Viewed user {user_id} from {request.remote_addr}')
        else:
            content = '<div class="card"><p>User not found.</p></div>'
    else:
        users = conn.execute('SELECT id, username, role FROM htb_users').fetchall()
        rows = ''.join(f'<tr><td>{u["id"]}</td><td><a href="/htb/users/{u["id"]}" style="color:{COLORS["cyan"]}">{u["username"]}</a></td><td>{u["role"]}</td></tr>' for u in users)
        content = f'''
<div class="card">
<h2>&gt;_ User Directory</h2>
<table><tr><th>ID</th><th>Username</th><th>Role</th></tr>{rows}</table>
</div>'''
    conn.close()
    return render_template_string(BASE_TPL, title='Users', active_page='users',
                                  content=content, colors=COLORS)

# ============================================================
# Step 3: SQL INJECTION - Authentication Bypass
# ============================================================

LOGIN_CONTENT = '''
<div class="card">
<h2>&gt;_ Employee Login</h2>
<form method="POST" action="/htb/login">
<label>Username</label>
<input type="text" name="username" placeholder="Enter username" required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit" class="btn">Login</button>
</form>
{% if result %}
<div class="result {{ result_class }}">{{ result }}</div>
{% endif %}
</div>
<div class="card">
<h2>&gt;_ Password Recovery</h2>
<p>Forgot your password? Contact your administrator or check your password hint in your profile.</p>
</div>
'''

@htb.route('/login', methods=['GET', 'POST'])
def htb_login():
    result = None
    result_class = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABLE: SQL Injection in login query
        conn = get_db()
        query = f"SELECT * FROM htb_users WHERE username='{username}' AND password='{hashlib.sha256(password.encode()).hexdigest()}'"
        try:
            user = conn.execute(query).fetchone()
            if user:
                # Create session token
                token = hashlib.sha256(f"{user['username']}{time.time()}{os.urandom(16).hex()}".encode()).hexdigest()
                conn.execute('INSERT INTO htb_sessions (user_id, token, is_admin) VALUES (?,?,?)',
                             (user['id'], token, 1 if user['role'] == 'admin' else 0))
                conn.commit()
                session['htb_token'] = token
                result = f"Welcome, {user['username']}! Role: {user['role']}\\nSession: {token[:16]}..."
                result_class = 'ok'
                log_action('login_success', f'User {user["username"]} from {request.remote_addr}')
            else:
                result = "Invalid credentials."
                result_class = 'error'
                log_action('login_failed', f'Username: {username} from {request.remote_addr}')
        except Exception as e:
            result = f"Error: {e}"
            result_class = 'error'
            log_action('login_error', str(e))
        conn.close()

    return render_template_string(BASE_TPL, title='Login', active_page='login',
        content=render_template_string(LOGIN_CONTENT, result=result, result_class=result_class),
        colors=COLORS)

# ============================================================
# Step 4: STORED XSS - Inject Malicious Payload via Profile
# ============================================================

PROFILE_CONTENT = '''
<div class="card">
<h2>&gt;_ My Profile</h2>
{% if user %}
<form method="POST" action="/htb/profile">
<label>Username</label>
<input type="text" value="{{ user['username'] }}" disabled>
<label>Email</label>
<input type="email" name="email" value="{{ user.get('email','') }}">
<label>Bio</label>
<textarea name="bio" placeholder="Tell us about yourself...">{{ user.get('bio','') }}</textarea>
<button type="submit" class="btn">Update Profile</button>
</form>
{% if user.get('bio') %}
<h3>Preview</h3>
<div class="result">{{ bio_preview|safe }}</div>
{% endif %}
{% else %}
<p>Please <a href="/htb/login" style="color:{{ colors.cyan }}">login</a> first.</p>
{% endif %}
</div>
<div class="card">
<h2>&gt;_ Profile Visitors</h2>
<p>Your profile is periodically reviewed by our security team for quality assurance.</p>
<p><em>Last reviewed: {{ last_review }}</em></p>
</div>
'''

@htb.route('/profile', methods=['GET', 'POST'])
def htb_profile():
    token = session.get('htb_token')
    user = get_user_by_token(token)

    if request.method == 'POST' and user:
        email = request.form.get('email', '')
        bio = request.form.get('bio', '')
        # VULNERABLE: No sanitization of bio field - stored XSS
        conn = get_db()
        conn.execute('UPDATE htb_users SET email=?, bio=? WHERE id=?', (email, bio, user['id']))
        conn.commit()
        # Fetch updated user
        user = conn.execute('SELECT * FROM htb_users WHERE id=?', (user['id'],)).fetchone()
        conn.close()
        log_action('profile_update', f'User {user["username"]} updated profile')
        flash('Profile updated!', 'ok')
    elif user:
        conn = get_db()
        user = conn.execute('SELECT * FROM htb_users WHERE id=?', (user['id'],)).fetchone()
        conn.close()

    bio_preview = user['bio'] if user and user['bio'] else '<em>No bio set.</em>'
    return render_template_string(BASE_TPL, title='Profile', active_page='profile',
        content=render_template_string(PROFILE_CONTENT,
            user=user if user else None,
            bio_preview=bio_preview,
            last_review=time.strftime('%Y-%m-%d %H:%M:%S'),
            colors=COLORS),
        colors=COLORS)

# ============================================================
# Step 5: ADMIN PANEL - CSRF + SSRF
# ============================================================

ADMIN_CONTENT = '''
<div class="card">
<h2>&gt;_ Admin Control Panel</h2>
{% if is_admin %}
<p style="color:{{ colors.green }}">✓ Authenticated as administrator</p>

<h3>System Configuration</h3>
<form method="POST" action="/htb/admin/config">
<table>
{% for c in config %}
<tr>
<td><code>{{ c['key'] }}</code></td>
<td>
<input type="text" name="config_{{ c['key'] }}" value="{{ c['value'] }}" style="width:200px;">
</td>
<td><small style="color:{{ colors.text }}">by {{ c['updated_by'] }}</small></td>
</tr>
{% endfor %}
</table>
<button type="submit" class="btn">Save Configuration</button>
</form>

<h3>Service Health Check</h3>
<form method="POST" action="/htb/admin/health">
<label>URL to check</label>
<input type="text" name="url" placeholder="http://127.0.0.1:8080/dev/ping?host=127.0.0.1">
<button type="submit" class="btn btn-blue">Check Health</button>
</form>
{% if health_result %}
<div class="result">{{ health_result }}</div>
{% endif %}

<h3>Audit Log (Last 20)</h3>
<div class="result" style="max-height:300px;">{{ audit_log }}</div>

{% else %}
<p style="color:{{ colors.red }}">✗ Access denied. Admin privileges required.</p>
<p>Hint: The security bot reviews profiles regularly. Maybe you can get its attention...</p>
{% endif %}
</div>
'''

@htb.route('/admin', methods=['GET', 'POST'])
def htb_admin():
    token = session.get('htb_token')
    user = get_user_by_token(token)
    is_admin = user and user['role'] in ('admin', 'bot')

    config = []
    health_result = None
    audit_log = ''

    if is_admin:
        conn = get_db()
        config = conn.execute('SELECT * FROM htb_config ORDER BY key').fetchall()
        logs = conn.execute('SELECT * FROM htb_audit_log ORDER BY id DESC LIMIT 20').fetchall()
        audit_log = '\\n'.join(f"[{l['created_at']}] {l['action']}: {l['detail']} (IP: {l['ip']})" for l in logs)
        conn.close()

    return render_template_string(BASE_TPL, title='Admin', active_page='admin',
        content=render_template_string(ADMIN_CONTENT,
            is_admin=is_admin, config=config,
            health_result=health_result, audit_log=audit_log, colors=COLORS),
        colors=COLORS)

@htb.route('/admin/config', methods=['POST'])
def htb_admin_config():
    # VULNERABLE: No CSRF token validation
    # Attacker can craft a form on another page that submits here
    token = session.get('htb_token')
    user = get_user_by_token(token)
    if not user or user['role'] not in ('admin', 'bot'):
        abort(403)

    conn = get_db()
    configs = conn.execute('SELECT key FROM htb_config').fetchall()
    for c in configs:
        val = request.form.get(f'config_{c["key"]}', '')
        if val:
            conn.execute('UPDATE htb_config SET value=?, updated_by=?, updated_at=CURRENT_TIMESTAMP WHERE key=?',
                        (val, user['username'], c['key']))
    conn.commit()
    conn.close()
    log_action('config_update', f'Config changed by {user["username"]}')
    flash('Configuration updated!', 'ok')
    return redirect('/admin')

@htb.route('/admin/health', methods=['POST'])
def htb_admin_health():
    # VULNERABLE: SSRF - no URL validation, can access internal services
    token = session.get('htb_token')
    user = get_user_by_token(token)
    if not user or user['role'] not in ('admin', 'bot'):
        abort(403)

    url = request.form.get('url', '')
    if url:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={'User-Agent': 'CorpSec-HealthBot/1.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                result = f"Status: {resp.status}\\nHeaders: {dict(resp.headers)}\\n\\nBody:\\n{body[:3000]}"
        except Exception as e:
            result = f"Error: {e}"
        log_action('health_check', f'URL: {url} by {user["username"]}')

    # Re-render admin page with result
    conn = get_db()
    config = conn.execute('SELECT * FROM htb_config ORDER BY key').fetchall()
    logs = conn.execute('SELECT * FROM htb_audit_log ORDER BY id DESC LIMIT 20').fetchall()
    audit_log = '\\n'.join(f"[{l['created_at']}] {l['action']}: {l['detail']} (IP: {l['ip']})" for l in logs)
    conn.close()

    return render_template_string(BASE_TPL, title='Admin', active_page='admin',
        content=render_template_string(ADMIN_CONTENT,
            is_admin=True, config=config,
            health_result=result, audit_log=audit_log, colors=COLORS),
        colors=COLORS)

# ============================================================
# Step 6: DEV TOOLS - Command Injection (behind config flag)
# ============================================================

DEV_CONTENT = '''
<div class="card">
<h2>&gt;_ Developer Tools</h2>
{% if dev_enabled %}
<p style="color:{{ colors.green }}">Developer tools are enabled.</p>

<h3>Network Diagnostics</h3>
<form method="POST" action="/htb/dev/ping">
<label>Host</label>
<input type="text" name="host" placeholder="e.g. 127.0.0.1" required>
<button type="submit" class="btn">Ping</button>
</form>

<h3>DNS Lookup</h3>
<form method="POST" action="/htb/dev/dns">
<label>Domain</label>
<input type="text" name="domain" placeholder="e.g. corpsec.internal" required>
<button type="submit" class="btn">Lookup</button>
</form>

{% if result %}
<div class="result">{{ result }}</div>
{% endif %}

{% else %}
<p style="color:{{ colors.red }}">Developer tools are currently disabled.</p>
<p>Contact an administrator to enable developer_tools configuration.</p>
{% endif %}
</div>
'''

@htb.route('/dev', methods=['GET'])
def htb_dev():
    dev_enabled = get_config('developer_tools') == 'enabled'
    return render_template_string(BASE_TPL, title='Dev Tools', active_page='dev',
        content=render_template_string(DEV_CONTENT, dev_enabled=dev_enabled, result=None, colors=COLORS),
        colors=COLORS)

@htb.route('/dev/ping', methods=['POST'])
def htb_dev_ping():
    # VULNERABLE: Command injection - only available when developer_tools enabled
    dev_enabled = get_config('developer_tools') == 'enabled'
    if not dev_enabled:
        flash('Developer tools are disabled.', 'err')
        return redirect('/dev')

    host = request.form.get('host', '')
    result = None
    if host:
        # VULNERABLE: Direct shell command injection
        try:
            cmd = f"ping -c 2 -W 3 {host}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=15)
            result = output.decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            result = "Command timed out."
        except Exception as e:
            result = f"Error: {e}"
        log_action('ping', f'Host: {host}')

    return render_template_string(BASE_TPL, title='Dev Tools', active_page='dev',
        content=render_template_string(DEV_CONTENT, dev_enabled=True, result=result, colors=COLORS),
        colors=COLORS)

@htb.route('/dev/dns', methods=['POST'])
def htb_dev_dns():
    dev_enabled = get_config('developer_tools') == 'enabled'
    if not dev_enabled:
        flash('Developer tools are disabled.', 'err')
        return redirect('/dev')

    domain = request.form.get('domain', '')
    result = None
    if domain:
        # VULNERABLE: Command injection via nslookup
        try:
            cmd = f"nslookup {domain}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
            result = output.decode('utf-8', errors='replace')
        except Exception as e:
            result = f"Error: {e}"
        log_action('dns_lookup', f'Domain: {domain}')

    return render_template_string(BASE_TPL, title='Dev Tools', active_page='dev',
        content=render_template_string(DEV_CONTENT, dev_enabled=True, result=result, colors=COLORS),
        colors=COLORS)

# ============================================================
# Step 7: FLAG - Requires RCE to read
# ============================================================

FLAG_CONTENT = '''
<div class="card">
<h2>&gt;_ Capture The Flag</h2>
<p>You've made it to the final step. The flag is hidden on the server.</p>

{% if flag %}
<div class="result ok" style="font-size:16px; text-align:center; padding:20px;">
🏆 {{ flag }} 🏆
</div>
{% else %}
<p>To get the flag, you need to achieve RCE on the server and read <code>/root/flag.txt</code></p>
<p>Try the command injection in Dev Tools with SSRF:</p>
<pre class="result">
# Step 1: Enable developer_tools via CSRF
# Step 2: Use SSRF to access /dev/ping
# Step 3: Inject command to read flag

# Payload example (via SSRF health check URL):
http://127.0.0.1:5000/htb/dev/ping

# With command injection in host parameter:
; cat /root/flag.txt
</pre>
{% endif %}
</div>
'''

@htb.route('/flag')
def htb_flag():
    # The flag can be obtained via RCE
    # We simulate this by checking if the user has triggered the RCE path
    flag = None
    token = session.get('htb_token')
    user = get_user_by_token(token)
    if user:
        conn = get_db()
        # Check if RCE was achieved (we track this via audit log)
        rce_log = conn.execute("SELECT * FROM htb_audit_log WHERE action='rce_achieved' AND ip=?", (request.remote_addr,)).fetchone()
        if rce_log:
            flag_row = conn.execute("SELECT flag_value FROM htb_flags WHERE flag_name='rce'").fetchone()
            flag = flag_row['flag_value'] if flag_row else None
        conn.close()

    return render_template_string(BASE_TPL, title='Flag', active_page='flag',
        content=render_template_string(FLAG_CONTENT, flag=flag, colors=COLORS),
        colors=COLORS)

# ============================================================
# Step 8: The main challenge page with walkthrough
# ============================================================

CHALLENGE_CONTENT = '''
<div class="card">
<h2>&gt;_ 🏴 Corporate Breach - Attack Chain Challenge</h2>
<span class="badge badge-insane">INSANE</span>
<p>Chain multiple vulnerabilities to achieve Remote Code Execution and capture the flag.</p>
<p>This challenge simulates a real-world corporate environment. Each step builds on the previous one.</p>
</div>

<div class="card">
<h2>&gt;_ Attack Chain Overview</h2>

<div class="step">
<div class="step-num">1</div>
<div class="step-content">
<h4>Reconnaissance - Information Leakage</h4>
<p>Find the debug endpoint that leaks internal API routes and service information. No auth required.</p>
<span class="badge badge-easy">Easy</span> <span class="badge badge-easy">Info Leak</span>
</div>
</div>

<div class="step">
<div class="step-num">2</div>
<div class="step-content">
<h4>IDOR - Insecure Direct Object Reference</h4>
<p>Access other users' profiles. Find password hints and internal notes that reveal credentials.</p>
<span class="badge badge-easy">Easy</span> <span class="badge badge-easy">IDOR</span>
</div>
</div>

<div class="step">
<div class="step-num">3</div>
<div class="step-content">
<h4>SQL Injection - Authentication Bypass</h4>
<p>Use the credentials found in Step 2 to bypass authentication via SQL injection.</p>
<span class="badge badge-med">Medium</span> <span class="badge badge-med">SQLi</span>
</div>
</div>

<div class="step">
<div class="step-num">4</div>
<div class="step-content">
<h4>Stored XSS - Cookie Theft</h4>
<p>Inject a JavaScript payload in your profile bio. The security bot (with admin rights) will visit your profile.</p>
<span class="badge badge-med">Medium</span> <span class="badge badge-med">XSS</span>
</div>
</div>

<div class="step">
<div class="step-num">5</div>
<div class="step-content">
<h4>CSRF - Privilege Escalation</h4>
<p>Use the stolen admin cookie to access the admin panel and enable developer tools (no CSRF protection).</p>
<span class="badge badge-med">Medium</span> <span class="badge badge-med">CSRF</span>
</div>
</div>

<div class="step">
<div class="step-num">6</div>
<div class="step-content">
<h4>SSRF - Internal Network Reconnaissance</h4>
<p>Use the admin health check feature to scan internal services and discover the dev server.</p>
<span class="badge badge-hard">Hard</span> <span class="badge badge-hard">SSRF</span>
</div>
</div>

<div class="step">
<div class="step-num">7</div>
<div class="step-content">
<h4>Command Injection - Initial Foothold</h4>
<p>The dev server's ping tool is vulnerable to command injection. Chain with SSRF to reach it.</p>
<span class="badge badge-hard">Hard</span> <span class="badge badge-hard">CMDi</span>
</div>
</div>

<div class="step">
<div class="step-num">8</div>
<div class="step-content">
<h4>RCE - Full Compromise</h4>
<p>Read the flag from the server filesystem using the command injection chain.</p>
<span class="badge badge-insane">Insane</span> <span class="badge badge-insane">RCE</span>
</div>
</div>
</div>

<div class="card">
<h2>&gt;_ Getting Started</h2>
<ol>
<li>Start at the <a href="/htb/debug" style="color:{{ colors.cyan }}">Debug</a> endpoint to discover the attack surface</li>
<li>Browse the <a href="/htb/users" style="color:{{ colors.cyan }}">User Directory</a> to find interesting targets</li>
<li>Login at <a href="/htb/login" style="color:{{ colors.cyan }}">Login</a> to start the chain</li>
<li>Each step unlocks the next - follow the hints carefully</li>
</ol>
</div>

<div class="card">
<h2>&gt;_ Subflags</h2>
<p>Each step of the chain has its own subflag. Collect them all!</p>
<table>
<tr><th>Flag</th><th>Difficulty</th><th>Step</th></tr>
<tr><td><code>flag{r3c0n_1s_k3y_t0_3v3ryth1ng}</code></td><td><span class="badge badge-easy">Easy</span></td><td>Recon</td></tr>
<tr><td><code>flag{1d0r_l34ks_4ll_th3_th1ngs}</code></td><td><span class="badge badge-easy">Easy</span></td><td>IDOR</td></tr>
<tr><td><code>flag{sqli_byp4ss_m4st3r}</code></td><td><span class="badge badge-med">Medium</span></td><td>SQLi</td></tr>
<tr><td><code>flag{st0r3d_xss_c00k13_th13f}</code></td><td><span class="badge badge-med">Medium</span></td><td>XSS</td></tr>
<tr><td><code>flag{csrf_pr1v1l3g3_3sc4l4t10n}</code></td><td><span class="badge badge-med">Medium</span></td><td>CSRF</td></tr>
<tr><td><code>flag{ssrf_1nt3rn4l_n3tw0rk_sc4n}</code></td><td><span class="badge badge-hard">Hard</span></td><td>SSRF</td></tr>
<tr><td><code>flag{htb_ch41n_r34l_w0rld_pwn3d_g00d_j0b}</code></td><td><span class="badge badge-insane">Insane</span></td><td>RCE</td></tr>
</table>
</div>
'''

@htb.route('/home')
@htb.route('/')
def htb_home():
    return render_template_string(BASE_TPL, title='Corporate Breach', active_page='htb_home',
                                  content=CHALLENGE_CONTENT, colors=COLORS)

# ============================================================
# API v2 endpoints (also vulnerable)
# ============================================================

@htb.route('/api/v2/login', methods=['POST'])
def api_v2_login():
    """VULNERABLE: SQL Injection in API login"""
    username = request.json.get('username', '') if request.is_json else request.form.get('username', '')
    password = request.json.get('password', '') if request.is_json else request.form.get('password', '')

    conn = get_db()
    query = f"SELECT id, username, role FROM htb_users WHERE username='{username}' AND password='{hashlib.sha256(password.encode()).hexdigest()}'"
    try:
        user = conn.execute(query).fetchone()
        if user:
            token = hashlib.sha256(f"{user['username']}{time.time()}{os.urandom(16).hex()}".encode()).hexdigest()
            conn.execute('INSERT INTO htb_sessions (user_id, token, is_admin) VALUES (?,?,?)',
                        (user['id'], token, 1 if user['role'] in ('admin','bot') else 0))
            conn.commit()
            conn.close()
            return jsonify({'status': 'ok', 'token': token, 'user': user['username'], 'role': user['role']})
        conn.close()
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    except Exception as e:
        conn.close()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@htb.route('/api/v2/users/<int:user_id>')
def api_v2_users(user_id):
    """VULNERABLE: IDOR - no auth check"""
    conn = get_db()
    user = conn.execute('SELECT id, username, role, email, bio, password_hint, internal_notes FROM htb_users WHERE id=?',
                        (user_id,)).fetchone()
    conn.close()
    if user:
        return jsonify(dict(user))
    return jsonify({'error': 'Not found'}), 404

@htb.route('/api/v2/profile', methods=['POST'])
def api_v2_profile():
    """VULNERABLE: Stored XSS via bio update"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '') or request.form.get('token', '')
    user = get_user_by_token(token)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    bio = request.json.get('bio', '') if request.is_json else request.form.get('bio', '')
    conn = get_db()
    conn.execute('UPDATE htb_users SET bio=? WHERE id=?', (bio, user['id']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok', 'message': 'Profile updated'})

@htb.route('/api/v2/flag')
def api_v2_flag():
    """Get the final flag - requires RCE to have been achieved"""
    conn = get_db()
    rce_log = conn.execute("SELECT * FROM htb_audit_log WHERE action='rce_achieved' ORDER BY id DESC LIMIT 1").fetchone()
    if rce_log:
        flag = conn.execute("SELECT flag_value FROM htb_flags WHERE flag_name='rce'").fetchone()
        conn.close()
        return jsonify({'flag': flag['flag_value']})
    conn.close()
    return jsonify({'error': 'Achieve RCE first to get the flag'}), 403

# ============================================================
# Security Bot Simulation (visits profiles periodically)
# ============================================================

def security_bot():
    """Simulates a security bot that visits profiles - triggers XSS"""
    import urllib.request
    time.sleep(10)  # Wait for app to start
    while True:
        try:
            conn = sqlite3.connect(current_app.config['HTB_DATABASE'])
            conn.row_factory = sqlite3.Row
            # Get the bot's session token
            bot_session = conn.execute("SELECT token FROM htb_sessions WHERE user_id=(SELECT id FROM htb_users WHERE username='security_bot') ORDER BY id DESC LIMIT 1").fetchone()
            if not bot_session:
                # Create a session for the bot
                bot_user = conn.execute("SELECT id FROM htb_users WHERE username='security_bot'").fetchone()
                if bot_user:
                    token = hashlib.sha256(f"security_bot{time.time()}{os.urandom(16).hex()}".encode()).hexdigest()
                    conn.execute('INSERT INTO htb_sessions (user_id, token, is_admin) VALUES (?,?,1)', (bot_user['id'], token))
                    conn.commit()
                    bot_session = {'token': token}
            conn.close()

            if bot_session:
                # Visit user profiles (IDs 2-4)
                for uid in range(2, 5):
                    try:
                        req = urllib.request.Request(
                            f'http://127.0.0.1:5000/htb/users/{uid}',
                            headers={'Authorization': f'Bearer {bot_session["token"]}',
                                     'User-Agent': 'CorpSec-SecurityBot/2.0'}
                        )
                        urllib.request.urlopen(req, timeout=5)
                    except:
                        pass
        except:
            pass
        time.sleep(120)  # Visit every 2 minutes

# ============================================================
# Note: This module is a Blueprint. Import and register from app.py
# ============================================================
