import os
import subprocess
import sqlite3
import uuid
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, flash, abort
)
from werkzeug.utils import secure_filename
from bcrypt import hashpw, gensalt, checkpw

APP_VERSION = "1.0"
UPLOAD_FOLDER = 'data'
ALLOWED_EXTENSIONS = {'txt', 'log', 'pcap', 'csv', 'json', 'conf', 'evt', 'xml', 'lst', 'hash'}
BANNER = "INTERNAL AUTHORIZED USE ONLY — ALL ACTIONS LOGGED"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(32)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True

def get_db():
    db_path = 'users.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                username TEXT,
                action TEXT,
                target TEXT,
                timestamp TEXT
            )
        ''')

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def log_action(username, action, target=""):
    with get_db() as db:
        db.execute("INSERT INTO audit (username, action, target, timestamp) VALUES (?,?,?,?)",
                   (username, action, target, datetime.now().isoformat()))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_dir(username):
    path = os.path.join(app.config['UPLOAD_FOLDER'], username)
    os.makedirs(path, exist_ok=True)
    return path

def save_result(user, tool, content):
    fname = os.path.join(get_user_dir(user), f"{tool}_{uuid.uuid4().hex}.txt")
    with open(fname, "w") as f:
        f.write(content)
    return fname

def run_tool(command, user, tool_name, target, input_file=None):
    log_action(user, f"Ran tool: {tool_name}", target)
    try:
        if input_file:
            with open(input_file, 'rb') as f:
                result = subprocess.run(
                    command, shell=False, capture_output=True, text=True, timeout=300, stdin=f
                )
        else:
            result = subprocess.run(
                command, shell=False, capture_output=True, text=True, timeout=300
            )
        output = result.stdout + result.stderr
    except Exception as e:
        output = f"Error: {e}"
    save_result(user, tool_name, output)
    return output

@app.route("/")
@login_required
def index():
    return render_template("dashboard.html", banner=BANNER, username=session['username'], version=APP_VERSION)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password'].encode("utf8")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and checkpw(password, user['password'].encode("utf8")):
                session["username"] = username
                return redirect(url_for('index'))
        flash("Login failed. Check credentials.")
        return render_template("login.html", banner=BANNER)
    return render_template("login.html", banner=BANNER)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password'].encode("utf8")
        pwhash = hashpw(password, gensalt()).decode("utf8")
        try:
            with get_db() as db:
                db.execute("INSERT INTO users (username, password) VALUES (?,?)", (username, pwhash))
            flash("Registered! Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
    return render_template("register.html", banner=BANNER)

@app.route("/tool/<tool>", methods=["GET", "POST"])
@login_required
def tool(tool):
    user = session['username']
    output = ""
    template = f"tools/{tool}.html"
    # --- Recon & OSINT ---
    if tool == "nmap":
        if request.method == "POST":
            target = request.form.get("target", "").strip()
            args = ["nmap", "-sV", "--script=default", target]
            output = run_tool(args, user, tool, target)
    elif tool == "whois":
        if request.method == "POST":
            target = request.form.get("target", "").strip()
            args = ["whois", target]
            output = run_tool(args, user, tool, target)
    elif tool == "dnsrecon":
        if request.method == "POST":
            domain = request.form.get("domain", "").strip()
            args = ["dnsrecon", "-d", domain]
            output = run_tool(args, user, tool, domain)
    elif tool == "dig":
        if request.method == "POST":
            domain = request.form.get("domain", "").strip()
            record = request.form.get("record", "A").strip()
            args = ["dig", domain, record]
            output = run_tool(args, user, tool, domain)
    elif tool == "sublist3r":
        if request.method == "POST":
            domain = request.form.get("domain", "").strip()
            args = ["sublist3r", "-d", domain]
            output = run_tool(args, user, tool, domain)
    elif tool == "amass":
        if request.method == "POST":
            domain = request.form.get("domain", "").strip()
            args = ["amass", "enum", "-d", domain]
            output = run_tool(args, user, tool, domain)
    elif tool == "theharvester":
        if request.method == "POST":
            domain = request.form.get("domain", "").strip()
            source = request.form.get("source", "all").strip()
            limit = request.form.get("limit", "100").strip()
            args = ["theHarvester", "-d", domain, "-b", source, "-l", limit]
            output = run_tool(args, user, tool, domain)
    # --- Web App ---
    elif tool == "nikto":
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            args = ["nikto", "-host", url]
            output = run_tool(args, user, tool, url)
    elif tool == "dirsearch":
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            args = ["dirsearch", "-u", url]
            output = run_tool(args, user, tool, url)
    elif tool == "gobuster":
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            wordlist = request.form.get("wordlist", "/usr/share/wordlists/dirb/common.txt").strip()
            args = ["gobuster", "dir", "-u", url, "-w", wordlist]
            output = run_tool(args, user, tool, url)
    elif tool == "sqlmap":
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            args = ["sqlmap", "-u", url, "--batch", "--level=1"]
            output = run_tool(args, user, tool, url)
    elif tool == "xsser":
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            args = ["xsser", "--url", url]
            output = run_tool(args, user, tool, url)
    elif tool == "httpreq":
        if request.method == "POST":
            method = request.form.get("method", "GET").upper()
            url = request.form.get("url", "").strip()
            headers = request.form.get("headers", "")
            data = request.form.get("data", "")
            import requests
            try:
                req_headers = dict([h.split(": ", 1) for h in headers.splitlines() if ": " in h])
                if method == "GET":
                    resp = requests.get(url, headers=req_headers)
                else:
                    resp = requests.post(url, headers=req_headers, data=data)
                output = resp.text
            except Exception as e:
                output = f"Error: {e}"
    # --- Cracking ---
    elif tool == "hydra":
        if request.method == "POST":
            service = request.form.get("service", "")
            target = request.form.get("target", "")
            userlist = request.form.get("userlist", "")
            passlist = request.form.get("passlist", "")
            args = ["hydra", "-L", userlist, "-P", passlist, f"{target}", service]
            output = run_tool(args, user, tool, target)
    elif tool == "john":
        if request.method == "POST":
            hashfile = request.files.get("hashfile")
            if hashfile and allowed_file(hashfile.filename):
                filename = secure_filename(hashfile.filename)
                fpath = os.path.join(get_user_dir(user), filename)
                hashfile.save(fpath)
                args = ["john", fpath]
                output = run_tool(args, user, tool, fpath)
    elif tool == "hashcat":
        if request.method == "POST":
            hashfile = request.files.get("hashfile")
            mode = request.form.get("mode", "0")
            wordlist = request.form.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            if hashfile and allowed_file(hashfile.filename):
                filename = secure_filename(hashfile.filename)
                fpath = os.path.join(get_user_dir(user), filename)
                hashfile.save(fpath)
                args = ["hashcat", "-m", mode, fpath, wordlist, "--force"]
                output = run_tool(args, user, tool, fpath)
    elif tool == "hashid":
        if request.method == "POST":
            hashval = request.form.get("hashval", "")
            args = ["hashid", hashval]
            output = run_tool(args, user, tool, hashval)
    elif tool == "namethathash":
        if request.method == "POST":
            hashval = request.form.get("hashval", "")
            args = ["nth", hashval]
            output = run_tool(args, user, tool, hashval)
    elif tool == "wordlistmgr":
        if request.method == "POST":
            wfile = request.files.get("wfile")
            if wfile and allowed_file(wfile.filename):
                filename = secure_filename(wfile.filename)
                fpath = os.path.join(get_user_dir(user), filename)
                wfile.save(fpath)
                with open(fpath, "r", errors='ignore') as f:
                    preview = "".join([next(f) for _ in range(20)])
                output = f"Preview:\n{preview}"
    # --- Exploitation ---
    elif tool == "msfvenom":
        if request.method == "POST":
            payload = request.form.get("payload", "windows/shell_reverse_tcp")
            lhost = request.form.get("lhost", "")
            lport = request.form.get("lport", "4444")
            outformat = request.form.get("outformat", "exe")
            args = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", outformat]
            output = run_tool(args, user, tool, lhost)
    elif tool == "revshell":
        if request.method == "POST":
            lport = request.form.get("lport", "4444")
            output = f"Start a listener: <pre>nc -lvnp {lport}</pre>\nReverse shell payloads can be generated using msfvenom."
    elif tool == "encoder":
        if request.method == "POST":
            content = request.form.get("content", "")
            method = request.form.get("method", "base64")
            if method == "base64":
                import base64
                output = base64.b64encode(content.encode()).decode()
            elif method == "url":
                import urllib.parse
                output = urllib.parse.quote(content)
            elif method == "xor":
                key = request.form.get("key", "A")
                output = ''.join([chr(ord(c) ^ ord(key)) for c in content])
    elif tool == "sessionlog":
        userdir = get_user_dir(user)
        logs = [f for f in os.listdir(userdir) if f.startswith("msfvenom") or f.startswith("revshell")]
        output = "\n".join(logs)
    # --- Defense ---
    elif tool == "loganalyzer":
        if request.method == "POST":
            logfile = request.files.get("logfile")
            if logfile and allowed_file(logfile.filename):
                filename = secure_filename(logfile.filename)
                fpath = os.path.join(get_user_dir(user), filename)
                logfile.save(fpath)
                with open(fpath, "r", errors='ignore') as f:
                    output = "".join(f.readlines()[-40:])
    elif tool == "iocscanner":
        if request.method == "POST":
            logfile = request.files.get("logfile")
            ioc = request.form.get("ioc", "")
            if logfile and allowed_file(logfile.filename):
                filename = secure_filename(logfile.filename)
                fpath = os.path.join(get_user_dir(user), filename)
                logfile.save(fpath)
                with open(fpath, "r", errors='ignore') as f:
                    output = "\n".join([line for line in f if ioc in line])
    elif tool == "sigma":
        if request.method == "POST":
            output = "Sigma rule validation is not setup in this demo."
    elif tool == "assetinv":
        if request.method == "POST":
            asset = request.form.get("asset", "")
            status = request.form.get("status", "")
            output = f"Asset {asset} status updated to {status}"
    elif tool == "pcapview":
        if request.method == "POST":
            pcapfile = request.files.get("pcapfile")
            if pcapfile and allowed_file(pcapfile.filename):
                filename = secure_filename(pcapfile.filename)
                fpath = os.path.join(get_user_dir(user), filename)
                pcapfile.save(fpath)
                args = ["tshark", "-r", fpath, "-c", "50"]
                output = run_tool(args, user, tool, fpath)
    # --- Purple Team ---
    elif tool == "exercise":
        if request.method == "POST":
            scope = request.form.get("scope", "")
            rules = request.form.get("rules", "")
            output = f"Exercise scope: {scope}\nRules: {rules}"
    elif tool == "detectiongap":
        if request.method == "POST":
            red = request.form.get("red", "")
            blue = request.form.get("blue", "")
            output = "Compare Red/Blue: (Not implemented: would diff lists)"
    elif tool == "timeline":
        if request.method == "POST":
            steps = request.form.get("steps", "")
            output = f"Timeline:\n{steps}"
    elif tool == "notes":
        if request.method == "POST":
            notes = request.form.get("notes", "")
            output = f"Notes saved: {notes}"
    # --- Black Hat / C2 (lab only) ---
    elif tool == "empire":
        if request.method == "POST":
            action = request.form.get("action", "")
            params = request.form.get("params", "")
            if action == "status":
                args = ["empire", "--status"]
            elif action == "start":
                args = ["empire", "server", "start"] + params.split()
            elif action == "stop":
                args = ["empire", "server", "stop"] + params.split()
            elif action == "payload":
                args = ["empire", "generate", "stager"] + params.split()
            else:
                args = ["empire"]
            output = run_tool(args, user, tool, action)
    elif tool == "sliver":
        if request.method == "POST":
            action = request.form.get("action", "")
            params = request.form.get("params", "")
            if action == "status":
                args = ["sliver-server", "status"]
            elif action == "listener":
                args = ["sliver-server", "listener", "http", "--name", params] if params else ["sliver-server", "listener", "http"]
            elif action == "payload":
                args = ["sliver-client", "generate", "payload"] + params.split()
            else:
                args = ["sliver-server"]
            output = run_tool(args, user, tool, action)
    elif tool == "mythic":
        if request.method == "POST":
            action = request.form.get("action", "")
            params = request.form.get("params", "")
            if action == "status":
                args = ["mythic-cli", "status"]
            elif action == "payload":
                args = ["mythic-cli", "generate", "payload"] + params.split()
            else:
                args = ["mythic-cli"]
            output = run_tool(args, user, tool, action)
    # --- Reporting ---
    elif tool == "report":
        return redirect(url_for('report'))
    else:
        abort(404)
    return render_template(template, banner=BANNER, output=output)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    user = session['username']
    if 'file' not in request.files:
        flash("No file part")
        return redirect(request.referrer)
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(get_user_dir(user), filename)
        file.save(save_path)
        flash("File uploaded.")
        log_action(user, "Uploaded file", filename)
    else:
        flash("File type not allowed.")
    return redirect(request.referrer)

@app.route("/download/<path:filename>")
@login_required
def download(filename):
    user_dir = get_user_dir(session['username'])
    file_path = os.path.join(user_dir, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    abort(404)

@app.route("/report")
@login_required
def report():
    user = session['username']
    with get_db() as db:
        logs = db.execute("SELECT * FROM audit WHERE username=? ORDER BY timestamp DESC", (user,)).fetchall()
    return render_template("report.html", banner=BANNER, logs=logs)

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", banner=BANNER), 404

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=3434, debug=False)