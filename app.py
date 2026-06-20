# VulnLab - Intentionally Vulnerable Web Application
# FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY

import os
import sqlite3
import subprocess
import hashlib
import base64
import pickle
import re
from functools import wraps
from flask import (Flask, request, render_template_string, render_template,
                   redirect, url_for, session, flash, make_response, jsonify,
                   send_from_directory)
from werkzeug.utils import secure_filename

# Import HTB Challenge blueprint
from challenge import htb as htb_blueprint, init_db as init_htb_db

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_in_production'
app.config['UPLOAD_FOLDER'] = '/tmp/vulnlab_uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Register HTB Challenge blueprint
app.register_blueprint(htb_blueprint, url_prefix='/htb')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config['DATABASE'] = '/tmp/vulnlab.db'
app.config['HTB_DATABASE'] = '/tmp/htb_challenge.db'

# ============================================================
# Database helpers
# ============================================================

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            email TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            detail TEXT,
            ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    # Seed data
    users = [
        ('admin', hashlib.md5(b'admin123').hexdigest(), 'admin', 'admin@vulnlab.local'),
        ('john', hashlib.md5(b'password').hexdigest(), 'user', 'john@vulnlab.local'),
        ('jane', hashlib.md5(b'letmein').hexdigest(), 'user', 'jane@vulnlab.local'),
    ]
    for u in users:
        try:
            conn.execute('INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)', u)
        except:
            pass
    secrets = [
        ('Flag 1', 'flag{sql1_m4st3r}', 1),
        ('API Key', 'sk-secret-key-12345', 1),
        ('Database Password', 'db_p@ssw0rd!', 1),
    ]
    for s in secrets:
        try:
            conn.execute('INSERT INTO secrets (name, value, user_id) VALUES (?,?,?)', s)
        except:
            pass
    conn.commit()
    conn.close()

# ============================================================
# Templates
# ============================================================

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnLab - {{ title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #c9d1d9; }
        .navbar { background: #161b22; padding: 15px 30px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #30363d; }
        .navbar h1 { color: #58a6ff; font-size: 24px; }
        .navbar h1 span { color: #f85149; }
        .nav-links { display: flex; gap: 20px; }
        .nav-links a { color: #8b949e; text-decoration: none; font-size: 14px; transition: color 0.2s; }
        .nav-links a:hover { color: #58a6ff; }
        .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin-bottom: 20px; }
        .card h2 { color: #58a6ff; margin-bottom: 10px; }
        .card p { color: #8b949e; margin-bottom: 15px; }
        .btn { display: inline-block; padding: 8px 16px; background: #238636; color: white; border: none; border-radius: 6px; cursor: pointer; text-decoration: none; font-size: 14px; margin: 5px 5px 5px 0; }
        .btn:hover { background: #2ea043; }
        .btn-danger { background: #da3633; }
        .btn-danger:hover { background: #f85149; }
        .btn-blue { background: #1f6feb; }
        .btn-blue:hover { background: #388bfd; }
        input[type="text"], input[type="password"], input[type="email"], textarea, select {
            width: 100%; padding: 10px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; margin-bottom: 10px;
        }
        input:focus, textarea:focus { outline: none; border-color: #58a6ff; }
        textarea { min-height: 100px; resize: vertical; }
        .result { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin-top: 15px; white-space: pre-wrap; font-family: monospace; font-size: 13px; }
        .difficulty { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .diff-low { background: #238636; color: white; }
        .diff-medium { background: #9e6a03; color: white; }
        .diff-high { background: #da3633; color: white; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; background: #30363d; color: #8b949e; margin-right: 5px; }
        .flash { padding: 10px 15px; border-radius: 6px; margin-bottom: 15px; }
        .flash-success { background: #238636; color: white; }
        .flash-error { background: #da3633; color: white; }
        .flash-info { background: #1f6feb; color: white; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }
        th { color: #58a6ff; }
        .hint { background: #1c2128; border-left: 3px solid #9e6a03; padding: 10px 15px; margin: 10px 0; font-size: 13px; color: #8b949e; }
        label { display: block; margin-bottom: 5px; color: #8b949e; font-size: 13px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>Vuln<span>Lab</span></h1>
        <div class="nav-links">
            <a href="/">Home</a>
            <a href="/sql-injection">SQL Injection</a>
            <a href="/xss">XSS</a>
            <a href="/command-injection">Command Injection</a>
            <a href="/lfi">LFI</a>
            <a href="/file-upload">File Upload</a>
            <a href="/idor">IDOR</a>
            <a href="/csrf">CSRF</a>
            <a href="/deserialization">Deserialization</a>
            <a href="/ssrf">SSRF</a>
            <a href="/xxe">XXE</a>
            <a href="/login">Login</a>
        </div>
    </nav>
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
        {% for category, message in messages %}
        <div class="flash flash-{{ category }}">{{ message }}</div>
        {% endfor %}
        {% endif %}
        {% endwith %}
        {{ content | safe }}
    </div>
</body>
</html>
'''

HOME_CONTENT = '''
<div class="card">
    <h2>Welcome to VulnLab</h2>
    <p>An intentionally vulnerable web application for security training and education. Practice common web vulnerabilities in a safe, controlled environment.</p>
    <p><strong style="color: #f85149;">WARNING:</strong> This application is intentionally vulnerable. Do NOT deploy on a public server or expose to untrusted networks.</p>
</div>

<h2 style="margin-bottom: 20px; color: #c9d1d9;">Vulnerability Challenges</h2>
<div class="grid">
    <div class="card">
        <h2>SQL Injection</h2>
        <span class="difficulty diff-low">Low</span>
        <p>Bypass authentication and extract data using SQL injection attacks.</p>
        <a href="/sql-injection" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>Cross-Site Scripting (XSS)</h2>
        <span class="difficulty diff-low">Low</span>
        <p>Inject malicious scripts into web pages viewed by other users.</p>
        <a href="/xss" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>Command Injection</h2>
        <span class="difficulty diff-medium">Medium</span>
        <p>Execute arbitrary system commands through vulnerable input fields.</p>
        <a href="/command-injection" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>Local File Inclusion (LFI)</h2>
        <span class="difficulty diff-medium">Medium</span>
        <p>Include and read arbitrary files from the server filesystem.</p>
        <a href="/lfi" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>Unrestricted File Upload</h2>
        <span class="difficulty diff-high">High</span>
        <p>Upload malicious files to achieve remote code execution.</p>
        <a href="/file-upload" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>IDOR</h2>
        <span class="difficulty diff-low">Low</span>
        <p>Access other users' data by manipulating object references.</p>
        <a href="/idor" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>CSRF</h2>
        <span class="difficulty diff-medium">Medium</span>
        <p>Perform actions on behalf of authenticated users without consent.</p>
        <a href="/csrf" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>Insecure Deserialization</h2>
        <span class="difficulty diff-high">High</span>
        <p>Exploit deserialization of untrusted data to execute arbitrary code.</p>
        <a href="/deserialization" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>SSRF</h2>
        <span class="difficulty diff-medium">Medium</span>
        <p>Force the server to make requests to internal or external resources.</p>
        <a href="/ssrf" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card">
        <h2>XXE</h2>
        <span class="difficulty diff-high">High</span>
        <p>Inject malicious XML entities to read files or perform SSRF.</p>
        <a href="/xxe" class="btn btn-blue">Start Challenge</a>
    </div>
    <div class="card" style="border-color: #f85149; border-width: 2px;">
        <h2 style="color: #f85149;">🏴 HTB Challenge: Corporate Breach</h2>
        <span class="difficulty diff-high">Insane</span>
        <p>Chain 8 vulnerabilities: Info Leak → IDOR → SQLi → XSS → CSRF → SSRF → CMDi → RCE. HackTheBox style!</p>
        <a href="/htb" class="btn" style="background: #f85149; color: white;">Start Challenge</a>
    </div>
</div>
'''

# ============================================================
# Routes
# ============================================================

@app.route('/')
def home():
    return render_template_string(BASE_TEMPLATE, title='Home', content=HOME_CONTENT)

# ---- SQL Injection ----
SQLI_CONTENT = '''
<div class="card">
    <h2>SQL Injection Challenge</h2>
    <span class="difficulty diff-low">Low</span>
    <p>The login form below is vulnerable to SQL injection. Try to bypass authentication without knowing the password.</p>
    <div class="hint">Hint: Think about how the SQL query is constructed with your input.</div>
    <form method="POST" action="/sql-injection">
        <label>Username</label>
        <input type="text" name="username" placeholder="Enter username" required>
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter password" required>
        <button type="submit" class="btn">Login</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>SQL Injection occurs when user input is concatenated directly into SQL queries without proper sanitization.</p>
    <p><strong>Prevention:</strong> Use parameterized queries / prepared statements.</p>
</div>
'''

@app.route('/sql-injection', methods=['GET', 'POST'])
def sql_injection():
    result = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        # VULNERABLE: Direct string concatenation in SQL query
        conn = get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
        try:
            user = conn.execute(query).fetchone()
            if user:
                result = f"Login successful! Welcome, {user['username']} (role: {user['role']})"
                if user['role'] == 'admin':
                    result += "\\n\\nCongratulations! You found the admin account.\\nHere's your reward: flag{sql1_m4st3r}"
            else:
                result = "Login failed. Invalid credentials."
        except Exception as e:
            result = f"SQL Error: {e}"
        conn.close()
    return render_template_string(BASE_TEMPLATE, title='SQL Injection',
                                  content=render_template_string(SQLI_CONTENT, result=result))

# ---- XSS ----
XSS_CONTENT = '''
<div class="card">
    <h2>Cross-Site Scripting (XSS) Challenge</h2>
    <span class="difficulty diff-low">Low</span>
    <p>The comment section below is vulnerable to XSS. Try to execute JavaScript in the browser.</p>
    <div class="hint">Hint: Try injecting HTML script tags or event handlers.</div>
    <form method="POST" action="/xss">
        <label>Your Name</label>
        <input type="text" name="author" placeholder="Your name" required>
        <label>Comment</label>
        <textarea name="content" placeholder="Leave a comment..." required></textarea>
        <button type="submit" class="btn">Post Comment</button>
    </form>
</div>
{% if comments %}
<div class="card">
    <h2>Comments</h2>
    {% for comment in comments %}
    <div style="background: #0d1117; padding: 10px; border-radius: 6px; margin-bottom: 10px;">
        <strong>{{ comment['author'] }}</strong>: {{ comment['content']|safe }}
    </div>
    {% endfor %}
</div>
{% endif %}
<div class="card">
    <h2>Learn More</h2>
    <p>XSS occurs when untrusted data is included in a web page without proper escaping.</p>
    <p><strong>Prevention:</strong> Use context-aware output encoding, Content Security Policy (CSP).</p>
</div>
'''

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    conn = get_db()
    if request.method == 'POST':
        author = request.form.get('author', '')
        content = request.form.get('content', '')
        # VULNERABLE: No sanitization of user input
        conn.execute('INSERT INTO comments (author, content) VALUES (?, ?)', (author, content))
        conn.commit()
    comments = conn.execute('SELECT * FROM comments ORDER BY id DESC LIMIT 20').fetchall()
    conn.close()
    return render_template_string(BASE_TEMPLATE, title='XSS',
                                  content=render_template_string(XSS_CONTENT, comments=comments))

# ---- Command Injection ----
CMD_CONTENT = '''
<div class="card">
    <h2>Command Injection Challenge</h2>
    <span class="difficulty diff-medium">Medium</span>
    <p>This utility pings a host. The input is passed directly to the system shell.</p>
    <div class="hint">Hint: Shell metacharacters like ; && | might be useful.</div>
    <form method="POST" action="/command-injection">
        <label>Host to ping</label>
        <input type="text" name="host" placeholder="e.g. 127.0.0.1" required>
        <button type="submit" class="btn">Ping</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>Command injection occurs when user input is passed to a system shell without sanitization.</p>
    <p><strong>Prevention:</strong> Avoid shell execution, use allowlists, escape arguments.</p>
</div>
'''

@app.route('/command-injection', methods=['GET', 'POST'])
def command_injection():
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '')
        # VULNERABLE: Direct shell execution
        try:
            cmd = f"ping -c 1 {host}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
            result = output.decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            result = "Command timed out."
        except Exception as e:
            result = f"Error: {e}"
    return render_template_string(BASE_TEMPLATE, title='Command Injection',
                                  content=render_template_string(CMD_CONTENT, result=result))

# ---- LFI ----
LFI_CONTENT = '''
<div class="card">
    <h2>Local File Inclusion Challenge</h2>
    <span class="difficulty diff-medium">Medium</span>
    <p>This page includes files based on user input. Try to read sensitive files from the server.</p>
    <div class="hint">Hint: Think about path traversal sequences like ../</div>
    <form method="GET" action="/lfi">
        <label>File to view</label>
        <input type="text" name="file" placeholder="e.g. welcome.txt" value="welcome.txt">
        <button type="submit" class="btn">View File</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>LFI occurs when user input is used to construct file paths without proper validation.</p>
    <p><strong>Prevention:</strong> Use allowlists, chroot, validate and sanitize file paths.</p>
</div>
'''

@app.route('/lfi')
def lfi():
    result = None
    filename = request.args.get('file', 'welcome.txt')
    # VULNERABLE: No path validation
    try:
        # Create a welcome file if it doesn't exist
        welcome_path = '/tmp/vulnlab_welcome.txt'
        if not os.path.exists(welcome_path):
            with open(welcome_path, 'w') as f:
                f.write('Welcome to VulnLab! This is a safe file to read.')
        
        # Resolve relative to /tmp for the demo file, but allow traversal
        if filename == 'welcome.txt':
            filepath = welcome_path
        else:
            filepath = os.path.join('/tmp', filename) if not filename.startswith('/') else filename
        
        with open(filepath, 'r') as f:
            result = f.read()
    except FileNotFoundError:
        result = f"File not found: {filename}"
    except Exception as e:
        result = f"Error: {e}"
    return render_template_string(BASE_TEMPLATE, title='LFI',
                                  content=render_template_string(LFI_CONTENT, result=result))

# ---- File Upload ----
UPLOAD_CONTENT = '''
<div class="card">
    <h2>Unrestricted File Upload Challenge</h2>
    <span class="difficulty diff-high">High</span>
    <p>Upload a file. The server only checks the file extension, not the content.</p>
    <div class="hint">Hint: What happens if you upload a .php or .phtml file?</div>
    <form method="POST" action="/file-upload" enctype="multipart/form-data">
        <label>Select file to upload</label>
        <input type="file" name="file" required>
        <button type="submit" class="btn">Upload</button>
    </form>
    {% if message %}
    <div class="result">{{ message }}</div>
    {% endif %}
    {% if uploaded_files %}
    <div class="card">
        <h2>Uploaded Files</h2>
        {% for f in uploaded_files %}
        <a href="/uploads/{{ f }}" class="btn btn-blue" style="margin: 5px;">{{ f }}</a>
        {% endfor %}
    </div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>Unrestricted file upload allows attackers to upload executable files (web shells).</p>
    <p><strong>Prevention:</strong> Validate file types by content (magic bytes), not extension. Store outside web root.</p>
</div>
'''

@app.route('/file-upload', methods=['GET', 'POST'])
def file_upload():
    message = None
    if request.method == 'POST':
        if 'file' not in request.files:
            message = "No file selected."
        else:
            file = request.files['file']
            if file.filename == '':
                message = "No file selected."
            else:
                # VULNERABLE: Only checks extension, allows .php, .phtml, etc.
                filename = secure_filename(file.filename)
                ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                allowed = ['jpg', 'jpeg', 'png', 'gif', 'txt', 'pdf']
                if ext in allowed or ext == '':  # bug: empty extension bypasses
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    message = f"File uploaded successfully: {filename}"
                else:
                    # Still saves with modified name but doesn't block dangerous extensions properly
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    message = f"File uploaded: {filename}"
    
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template_string(BASE_TEMPLATE, title='File Upload',
                                  content=render_template_string(UPLOAD_CONTENT, message=message, uploaded_files=files))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---- IDOR ----
IDOR_CONTENT = '''
<div class="card">
    <h2>Insecure Direct Object Reference (IDOR) Challenge</h2>
    <span class="difficulty diff-low">Low</span>
    <p>View user profiles by changing the user ID. Try to access other users' data.</p>
    <div class="hint">Hint: The user ID is visible in the URL. Try changing it.</div>
    <form method="GET" action="/idor">
        <label>User ID</label>
        <input type="text" name="id" placeholder="e.g. 1" value="1">
        <button type="submit" class="btn">View Profile</button>
    </form>
    {% if user %}
    <div class="result">{{ user }}</div>
    {% endif %}
    {% if secret %}
    <div class="result" style="border-color: #f85149;">{{ secret }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>IDOR occurs when applications expose internal object references without access control.</p>
    <p><strong>Prevention:</strong> Implement authorization checks, use indirect references (UUIDs).</p>
</div>
'''

@app.route('/idor')
def idor():
    user_id = request.args.get('id', '1')
    user_info = None
    secret_info = None
    conn = get_db()
    # VULNERABLE: No authorization check
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user:
            user_info = f"ID: {user['id']}\\nUsername: {user['username']}\\nRole: {user['role']}\\nEmail: {user['email']}"
    except:
        pass
    
    try:
        secrets = conn.execute('SELECT * FROM secrets WHERE user_id = ?', (user_id,)).fetchall()
        if secrets:
            secret_info = "Secrets found:\\n"
            for s in secrets:
                secret_info += f"  {s['name']}: {s['value']}\\n"
    except:
        pass
    conn.close()
    return render_template_string(BASE_TEMPLATE, title='IDOR',
                                  content=render_template_string(IDOR_CONTENT, user=user_info, secret=secret_info))

# ---- CSRF ----
CSRF_CONTENT = '''
<div class="card">
    <h2>Cross-Site Request Forgery (CSRF) Challenge</h2>
    <span class="difficulty diff-medium">Medium</span>
    <p>Transfer funds between accounts. The form has no CSRF protection.</p>
    <div class="hint">Hint: Create a hidden auto-submitting form on another page.</div>
    {% if session.get('logged_in') %}
    <p>Logged in as: <strong>{{ session.get('username') }}</strong></p>
    <p>Balance: <strong>${{ balance }}</strong></p>
    <form method="POST" action="/csrf">
        <label>Recipient</label>
        <input type="text" name="to" placeholder="Recipient username">
        <label>Amount</label>
        <input type="text" name="amount" placeholder="Amount to transfer">
        <button type="submit" class="btn">Transfer</button>
    </form>
    {% else %}
    <p>Please <a href="/login">login</a> first.</p>
    {% endif %}
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>CSRF tricks authenticated users into performing unintended actions.</p>
    <p><strong>Prevention:</strong> Use anti-CSRF tokens, SameSite cookies, verify Origin header.</p>
</div>
'''

@app.route('/csrf', methods=['GET', 'POST'])
def csrf():
    result = None
    balance = 1000
    if not session.get('logged_in'):
        # Auto-login for demo purposes
        session['logged_in'] = True
        session['username'] = 'john'
        session['user_id'] = 2
    
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = request.form.get('amount', '0')
        # VULNERABLE: No CSRF token validation
        try:
            amount = int(amount)
            result = f"Transferred ${amount} to {to} from {session.get('username')}"
        except:
            result = "Invalid amount."
    
    return render_template_string(BASE_TEMPLATE, title='CSRF',
                                  content=render_template_string(CSRF_CONTENT, result=result, balance=balance))

# ---- Insecure Deserialization ----
DESER_CONTENT = '''
<div class="card">
    <h2>Insecure Deserialization Challenge</h2>
    <span class="difficulty diff-high">High</span>
    <p>The app deserializes user-supplied data. Try to exploit it.</p>
    <div class="hint">Hint: Python pickle can execute arbitrary code during deserialization.</div>
    <form method="POST" action="/deserialization">
        <label>Serialized Data (Base64 encoded)</label>
        <input type="text" name="data" placeholder="Enter base64 encoded pickle data">
        <button type="submit" class="btn">Deserialize</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>Insecure deserialization can lead to remote code execution, replay attacks, injection.</p>
    <p><strong>Prevention:</strong> Never deserialize untrusted data. Use JSON or signed data formats.</p>
</div>
'''

@app.route('/deserialization', methods=['GET', 'POST'])
def deserialization():
    result = None
    if request.method == 'POST':
        data = request.form.get('data', '')
        if data:
            # VULNERABLE: Deserializing untrusted pickle data
            try:
                decoded = base64.b64decode(data)
                obj = pickle.loads(decoded)
                result = f"Deserialized object: {obj}"
            except Exception as e:
                result = f"Deserialization error: {e}"
        else:
            result = "No data provided."
    return render_template_string(BASE_TEMPLATE, title='Deserialization',
                                  content=render_template_string(DESER_CONTENT, result=result))

# ---- SSRF ----
SSRF_CONTENT = '''
<div class="card">
    <h2>Server-Side Request Forgery (SSRF) Challenge</h2>
    <span class="difficulty diff-medium">Medium</span>
    <p>Fetch a URL. The server will make an HTTP request to any URL you provide.</p>
    <div class="hint">Hint: Try accessing internal services or metadata endpoints.</div>
    <form method="POST" action="/ssrf">
        <label>URL to fetch</label>
        <input type="text" name="url" placeholder="e.g. http://example.com">
        <button type="submit" class="btn">Fetch</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>SSRF allows attackers to make the server send requests to internal/external resources.</p>
    <p><strong>Prevention:</strong> Validate and restrict URLs, block internal IP ranges, use allowlists.</p>
</div>
'''

@app.route('/ssrf', methods=['GET', 'POST'])
def ssrf():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '')
        if url:
            # VULNERABLE: No URL validation
            try:
                import urllib.request
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    result = f"Status: {resp.status}\\n\\nContent (first 2000 chars):\\n{content[:2000]}"
            except Exception as e:
                result = f"Error: {e}"
        else:
            result = "No URL provided."
    return render_template_string(BASE_TEMPLATE, title='SSRF',
                                  content=render_template_string(SSRF_CONTENT, result=result))

# ---- XXE ----
XXE_CONTENT = '''
<div class="card">
    <h2>XML External Entity (XXE) Challenge</h2>
    <span class="difficulty diff-high">High</span>
    <p>Submit XML data. The server parses XML with external entities enabled.</p>
    <div class="hint">Hint: Define an external entity to read local files.</div>
    <form method="POST" action="/xxe">
        <label>XML Data</label>
        <textarea name="xml" placeholder="&lt;name&gt;John&lt;/name&gt;" style="min-height: 150px;"><?xml version="1.0"?>
<user>
    <name>John</name>
</user></textarea>
        <button type="submit" class="btn">Submit XML</button>
    </form>
    {% if result %}
    <div class="result">{{ result }}</div>
    {% endif %}
</div>
<div class="card">
    <h2>Learn More</h2>
    <p>XXE attacks exploit XML parsers that process external entities.</p>
    <p><strong>Prevention:</strong> Disable external entities and DTD processing in XML parsers.</p>
</div>
'''

@app.route('/xxe', methods=['GET', 'POST'])
def xxe():
    result = None
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        if xml_data:
            # VULNERABLE: Using lxml with resolve_entities=True
            try:
                from lxml import etree
                parser = etree.XMLParser(resolve_entities=True, no_network=False)
                tree = etree.fromstring(xml_data.encode(), parser)
                result = f"Parsed XML:\\n{etree.tostring(tree, pretty_print=True).decode()}"
            except ImportError:
                try:
                    from xml.etree import ElementTree
                    root = ElementTree.fromstring(xml_data)
                    result = f"Parsed XML: {ElementTree.tostring(root, encoding='unicode')}"
                except Exception as e:
                    result = f"Parse error: {e}"
            except Exception as e:
                result = f"Error: {e}"
        else:
            result = "No XML provided."
    return render_template_string(BASE_TEMPLATE, title='XXE',
                                  content=render_template_string(XXE_CONTENT, result=result))

# ---- Login / Session ----
LOGIN_CONTENT = '''
<div class="card">
    <h2>Login</h2>
    <form method="POST" action="/login">
        <label>Username</label>
        <input type="text" name="username" placeholder="Username" required>
        <label>Password</label>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" class="btn">Login</button>
    </form>
    {% if error %}
    <div class="flash flash-error">{{ error }}</div>
    {% endif %}
</div>
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=? AND password=?',
                           (username, hashlib.md5(password.encode()).hexdigest())).fetchone()
        conn.close()
        if user:
            session['logged_in'] = True
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash(f'Welcome back, {username}!', 'success')
            return redirect('/')
        else:
            error = 'Invalid credentials'
    return render_template_string(BASE_TEMPLATE, title='Login',
                                  content=render_template_string(LOGIN_CONTENT, error=error))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect('/')

# ============================================================
# API Endpoints (vulnerable)
# ============================================================

@app.route('/api/user', methods=['GET'])
def api_user():
    """VULNERABLE API: Returns user info based on username parameter"""
    username = request.args.get('username', '')
    if username:
        conn = get_db()
        # VULNERABLE: SQL injection in API
        user = conn.execute(f"SELECT id, username, email FROM users WHERE username='{username}'").fetchone()
        conn.close()
        if user:
            return jsonify(dict(user))
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'error': 'Username parameter required'}), 400

@app.route('/api/search', methods=['GET'])
def api_search():
    """VULNERABLE API: Search comments"""
    q = request.args.get('q', '')
    if q:
        conn = get_db()
        # VULNERABLE: SQL injection
        results = conn.execute(
            f"SELECT * FROM comments WHERE content LIKE '%{q}%' OR author LIKE '%{q}%'"
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in results])
    return jsonify({'error': 'Query parameter required'}), 400

# ============================================================
# Main
# ============================================================

if __name__ == '__main__':
    with app.app_context():
        init_db()
        init_htb_db()
    # Start HTB security bot
    from challenge import security_bot
    import threading
    bot_thread = threading.Thread(target=security_bot, daemon=True)
    bot_thread.start()
    print("VulnLab starting...")
    print("HTB Challenge: Corporate Breach enabled at /htb")
    print("WARNING: This is an intentionally vulnerable application!")
    print("Do NOT expose to untrusted networks.")
    app.run(host='0.0.0.0', port=5000, debug=True)
