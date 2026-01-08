from flask import (
    Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_file
)
import os
import json
import sqlite3
import datetime as dt
import socket
import threading
import psutil
import platform
import time
import csv
import io
import logging
from logging.handlers import RotatingFileHandler

# --- SECURITY ENHANCEMENTS ---
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# --- IMPORT CUSTOM MODULES ---
import scanner
import integrity
from forms import (
    RegistrationForm, LoginForm, ForgotPasswordForm, 
    ChangePasswordForm, PortScanForm, FileIntegrityForm
)

# ---------------- FLASK APP SETUP ----------------
app = Flask(__name__)

# --- SECURITY: Secret key from environment variable ---
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey-change-in-production')

if app.secret_key == 'supersecretkey-change-in-production':
    app.logger.warning("⚠️  WARNING: Using default secret key. Set SECRET_KEY in .env file!")

# --- DATABASE FILE ---
DB_FILE = os.getenv('DB_FILE', 'security_toolkit.db')

# --- CSRF PROTECTION ---
csrf = CSRFProtect(app)

# Exempt JSON API endpoints from CSRF (for AJAX requests)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

# --- RATE LIMITING ---
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv('RATELIMIT_STORAGE_URL', 'memory://'),
    enabled=os.getenv('RATELIMIT_ENABLED', 'true').lower() == 'true'
)

# ---------------- LOGGING SETUP ----------------
def setup_logging():
    """Configure application logging with rotation"""
    log_file = os.getenv('LOG_FILE', 'security_toolkit.log')
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Set log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler with rotation (10MB max, keep 5 backups)
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    
    # Configure app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(level)
    
    app.logger.info("=" * 60)
    app.logger.info("Security Toolkit started")
    app.logger.info(f"Log level: {log_level}")
    app.logger.info("=" * 60)

setup_logging()

# ---------------- DATABASE SETUP ----------------
def init_db():
    """Initialize database tables"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT, start_port INT, end_port INT, timestamp TEXT, results TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT, results TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS file_integrity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    directory TEXT, algorithm TEXT, baseline TEXT, timestamp TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS network_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload REAL, download REAL, timestamp TEXT
                )
            """)
            conn.commit()
            app.logger.info("Database initialized successfully")
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")
        raise

init_db()

# ---------------- DEFAULT ADMIN ----------------
def ensure_default_admin():
    """Create default admin user if no users exist"""
    default_user = os.getenv('DEFAULT_ADMIN_USERNAME', 'admin')
    default_pass = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin123')
    
    try:
        hashed = generate_password_hash(default_pass, method='pbkdf2:sha256')
        
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM users")
            if c.fetchone()[0] == 0:
                c.execute("INSERT INTO users (username, password) VALUES (?,?)", (default_user, hashed))
                conn.commit()
                app.logger.info(f"Default admin created: {default_user}")
    except Exception as e:
        app.logger.error(f"Failed to create default admin: {e}")

ensure_default_admin()

# ---------------- UTILITIES ----------------
def login_required(func):
    """Decorator to require login for routes"""
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            app.logger.warning(f"Unauthorized access attempt to {request.path}")
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_user():
    """Make current user available in all templates"""
    return dict(current_user=session.get("user"))

# ---------------- AUTH ROUTES ----------------
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def register():
    """User registration with validation"""
    form = RegistrationForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        
        app.logger.info(f"Registration attempt for username: {username}")
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password) VALUES (?,?)", (username, hashed_pw))
                conn.commit()
                app.logger.info(f"User registered successfully: {username}")
                flash("Registration successful. Please login.", "success")
                return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            app.logger.warning(f"Registration failed - username exists: {username}")
            flash("Username already exists.", "danger")
        except Exception as e:
            app.logger.error(f"Registration error: {e}")
            flash("Registration failed. Please try again.", "danger")
    
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """User login with rate limiting"""
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        
        app.logger.info(f"Login attempt for username: {username}")
        
        try:
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute("SELECT password FROM users WHERE username=?", (username,))
                row = c.fetchone()
            
            if row and check_password_hash(row[0], password):
                session["user"] = username
                app.logger.info(f"Login successful: {username}")
                flash(f"Welcome, {username}!", "success")
                return redirect(url_for("dashboard"))
            else:
                app.logger.warning(f"Login failed - invalid credentials: {username}")
                flash("Invalid username or password.", "danger")
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            flash("Login failed. Please try again.", "danger")
    
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    """User logout"""
    username = session.get("user", "Unknown")
    session.pop("user", None)
    app.logger.info(f"User logged out: {username}")
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

# ---------------- FORGOT PASSWORD ----------------
@app.route("/forgot_password", methods=["GET", "POST"])
@limiter.limit("3 per hour")
def forgot_password():
    """Password reset with rate limiting"""
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        new_password = form.new_password.data
        
        app.logger.info(f"Password reset attempt for username: {username}")
        
        hashed_new = generate_password_hash(new_password, method='pbkdf2:sha256')

        try:
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute("SELECT id FROM users WHERE username=?", (username,))
                user = c.fetchone()
                
                if not user:
                    app.logger.warning(f"Password reset failed - user not found: {username}")
                    return render_template("forgot_password.html", form=form, error="Username not found.")
                
                c.execute("UPDATE users SET password=? WHERE username=?", (hashed_new, username))
                conn.commit()
                app.logger.info(f"Password reset successful: {username}")

            return render_template("forgot_password.html", form=form, message="Password reset successful! You can now log in.")
        except Exception as e:
            app.logger.error(f"Password reset error: {e}")
            return render_template("forgot_password.html", form=form, error="Password reset failed. Please try again.")

    return render_template("forgot_password.html", form=form)

# ---------------- CHANGE PASSWORD (LOGGED IN) ----------------
@app.route("/api/change_password", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def api_change_password():
    """Change password for logged-in user"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        username = session.get("user")
        
        app.logger.info(f"Password change attempt for user: {username}")
        
        try:
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute("SELECT password FROM users WHERE username=?", (username,))
                row = c.fetchone()
                
                if not row or not check_password_hash(row[0], current_password):
                    app.logger.warning(f"Password change failed - incorrect current password: {username}")
                    return jsonify({"success": False, "error": "Current password is incorrect"}), 400
                
                hashed_new = generate_password_hash(new_password, method='pbkdf2:sha256')
                c.execute("UPDATE users SET password=? WHERE username=?", (hashed_new, username))
                conn.commit()
                app.logger.info(f"Password changed successfully: {username}")
            
            return jsonify({"success": True, "message": "Password changed successfully!"})
        except Exception as e:
            app.logger.exception("Password change failed")
            return jsonify({"success": False, "error": str(e)}), 500
    
    errors = form.errors
    return jsonify({"success": False, "error": str(errors)}), 400

# ---------------- USER ACTIVITY STATS ----------------
@app.route("/api/user_activity_stats")
@login_required
def api_user_activity_stats():
    """Get user activity statistics"""
    try:
        username = session.get("user")
        
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            
            c.execute("SELECT COUNT(*) FROM port_scans")
            total_port_scans = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM audits")
            total_audits = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM file_integrity")
            total_file_checks = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM network_logs")
            total_network_logs = c.fetchone()[0]
            
            c.execute("SELECT timestamp FROM port_scans ORDER BY id DESC LIMIT 1")
            last_port_scan = c.fetchone()
            
            c.execute("SELECT timestamp FROM audits ORDER BY id DESC LIMIT 1")
            last_audit = c.fetchone()
            
            c.execute("SELECT timestamp FROM file_integrity ORDER BY id DESC LIMIT 1")
            last_file_check = c.fetchone()
            
            c.execute("SELECT timestamp FROM network_logs ORDER BY id DESC LIMIT 1")
            last_network_log = c.fetchone()
            
            return jsonify({
                "username": username,
                "total_port_scans": total_port_scans,
                "total_audits": total_audits,
                "total_file_checks": total_file_checks,
                "total_network_logs": total_network_logs,
                "last_port_scan": last_port_scan[0] if last_port_scan else "Never",
                "last_audit": last_audit[0] if last_audit else "Never",
                "last_file_check": last_file_check[0] if last_file_check else "Never",
                "last_network_log": last_network_log[0] if last_network_log else "Never",
                "total_activities": total_port_scans + total_audits + total_file_checks + total_network_logs
            })
    
    except Exception as e:
        app.logger.exception("User activity stats failed")
        return jsonify({"error": str(e)}), 500

# ---------------- DASHBOARD ----------------
@app.route("/")
@login_required
def dashboard():
    """Main dashboard"""
    app.logger.info(f"Dashboard accessed by user: {session.get('user')}")
    return render_template("index.html")

# ---------------- PORT SCANNER ----------------
SUSPICIOUS_PORTS = {
    21: "FTP - Unencrypted file transfer",
    22: "SSH - Potential unauthorized access",
    23: "Telnet - Unencrypted remote access",
    25: "SMTP - Email server, spam risk",
    53: "DNS - Potential amplification attack",
    80: "HTTP - Unencrypted web traffic",
    135: "MS RPC - Windows vulnerability",
    139: "NetBIOS - Windows file sharing",
    443: "HTTPS - Web traffic (check certificate)",
    445: "SMB - WannaCry ransomware vector",
    3389: "RDP - Remote desktop, brute force target",
    5900: "VNC - Remote desktop access",
    8080: "HTTP-Alt - Common web proxy",
    1433: "MS SQL - Database exposure",
    3306: "MySQL - Database exposure",
    5432: "PostgreSQL - Database exposure",
    6379: "Redis - Database exposure",
    27017: "MongoDB - Database exposure",
}

@app.route("/api/scan_ports", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_scan_ports():
    """Port scanning with validation"""
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Manual validation instead of form
        host = data.get("host", "127.0.0.1")
        start_port = int(data.get("start_port", 1))
        end_port = int(data.get("end_port", 1024))
        timeout = float(data.get("timeout", 1.0))
        
        # Basic validation
        if start_port < 1:
            start_port = 1
        if end_port > 65535:
            end_port = 65535
        if end_port < start_port:
            return jsonify({"error": "end_port must be >= start_port"}), 400
        
        username = session.get("user")
        app.logger.info(f"Port scan initiated by {username}: {host}:{start_port}-{end_port}")

        scan_data = scanner.run_port_scan(
            host=host,
            start_port=start_port,
            end_port=end_port,
            threads=100,
            timeout=timeout
        )

        enhanced_results = []
        for result in scan_data["results"]:
            if result["status"] != "OPEN":
                continue
            
            port = result["port"]
            is_suspicious = port in SUSPICIOUS_PORTS
            warning = SUSPICIOUS_PORTS.get(port, "")
            
            result["suspicious"] = is_suspicious
            result["warning"] = warning
            enhanced_results.append(result)

        timestamp = scan_data["timestamp"]
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO port_scans (host, start_port, end_port, timestamp, results) VALUES (?,?,?,?,?)",
                (host, start_port, end_port, timestamp, json.dumps(enhanced_results)),
            )
            conn.commit()
        
        app.logger.info(f"Port scan completed: {len(enhanced_results)} open ports found")
        return jsonify({"timestamp": timestamp, "results": enhanced_results})
        
    except Exception as e:
        app.logger.error(f"Port scan failed: {e}")
        return jsonify({"error": str(e)}), 500

# ---------------- FILE INTEGRITY ----------------
@app.route("/api/create_baseline", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def api_create_baseline():
    """Create file integrity baseline with validation"""
    try:
        # Get JSON data from request
        data = request.get_json() or {}
        directory = data.get("directory", ".") or "."
        algorithm = data.get("algorithm", "sha256") or "sha256"
        
        username = session.get("user")
        app.logger.info(f"Baseline creation initiated by {username}: {directory}")

        baseline = integrity.create_baseline(directory, algorithm)
        timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO file_integrity (directory, algorithm, baseline, timestamp) VALUES (?,?,?,?)",
                (directory, algorithm, json.dumps(baseline), timestamp),
            )
            conn.commit()
        
        app.logger.info(f"Baseline created: {len(baseline)} files")
        return jsonify({"status": "Baseline created", "timestamp": timestamp, "files": len(baseline)})
        
    except Exception as e:
        app.logger.error(f"Baseline creation failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan_changes")
@login_required
@limiter.limit("20 per hour")
def api_scan_changes():
    """Scan for file integrity changes"""
    try:
        directory = "."
        algorithm = "sha256"
        
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT directory, algorithm FROM file_integrity ORDER BY id DESC LIMIT 1")
            row = c.fetchone()
            if row:
                directory = row[0]
                algorithm = row[1]

        username = session.get("user")
        app.logger.info(f"File integrity scan by {username}: {directory}")
        
        scan_results = integrity.scan_for_changes(directory, algorithm)
        
        if "error" in scan_results:
            return jsonify({"results": [f"⚠️ {scan_results['error']}"]})

        formatted_output = []
        
        if scan_results["modified"]:
            formatted_output.append("⚠️ MODIFIED FILES:")
            formatted_output.extend([f"   - {f}" for f in scan_results["modified"]])
            
        if scan_results["removed"]:
            formatted_output.append("❌ DELETED FILES:")
            formatted_output.extend([f"   - {f}" for f in scan_results["removed"]])
            
        if scan_results["added"]:
            formatted_output.append("✅ NEW FILES:")
            formatted_output.extend([f"   - {f}" for f in scan_results["added"]])

        if not formatted_output:
            formatted_output.append("✅ System Clean: No changes detected since last baseline.")
        else:
            formatted_output.insert(0, f"Scan Report ({scan_results['summary']})")

        app.logger.info(f"File integrity scan completed: {scan_results['summary']}")
        return jsonify({"results": formatted_output})
        
    except Exception as e:
        app.logger.error(f"File integrity scan failed: {e}")
        return jsonify({"error": "Scan failed"}), 500

# ---------------- SYSTEM INFO / AUDIT ----------------
def _gather_system_info():
    """Gather system information"""
    try:
        os_name = platform.system() or "Unknown"
        release = platform.release() or "Unknown"
        cpu_desc = platform.processor() or f"{psutil.cpu_count(logical=True)} core(s)"
        memory_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        ram_usage = psutil.virtual_memory().percent
        boot_time = dt.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        uptime_seconds = time.time() - psutil.boot_time()
        uptime = str(dt.timedelta(seconds=int(uptime_seconds)))
        cpu_usage = psutil.cpu_percent(interval=0.5)
        
        return {
            "os": os_name,
            "release": release,
            "cpu": cpu_desc,
            "ram": memory_gb,
            "ram_usage": f"{ram_usage}%",
            "boot_time": boot_time,
            "uptime": uptime,
            "cpu_usage": f"{cpu_usage}%"
        }
    except Exception as e:
        raise RuntimeError(f"System info collection failed: {e}")

@app.route("/api/run_audit")
@login_required
@limiter.limit("30 per hour")
def api_run_audit():
    """Run system audit"""
    try:
        username = session.get("user")
        app.logger.info(f"System audit initiated by {username}")
        
        info = _gather_system_info()
        timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO audits (timestamp, results) VALUES (?,?)", (timestamp, json.dumps(info)))
            conn.commit()
        
        app.logger.info("System audit completed")
        return jsonify(info)
    except Exception as e:
        app.logger.exception("Audit failed")
        return jsonify({"error": f"Audit failed: {e}"}), 500

# ---------------- NETWORK MONITOR ----------------
@app.route("/api/network_info")
@login_required
@limiter.limit("60 per minute")
def api_network_info():
    """Get network information"""
    try:
        n1 = psutil.net_io_counters()
        up1, down1 = n1.bytes_sent, n1.bytes_recv
        time.sleep(1)
        n2 = psutil.net_io_counters()
        up2, down2 = n2.bytes_sent, n2.bytes_recv

        upload_kb_s = round((up2 - up1) / 1024.0, 2)
        download_kb_s = round((down2 - down1) / 1024.0, 2)
        timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO network_logs (upload, download, timestamp) VALUES (?,?,?)", 
                        (upload_kb_s, download_kb_s, timestamp))
            conn.commit()

        return jsonify({
            "upload": upload_kb_s,
            "download": download_kb_s,
            "timestamp": timestamp
        })
    except Exception as e:
        app.logger.exception("Network info failed")
        return jsonify({"error": str(e)}), 500

# ---------------- DASHBOARD STATISTICS ----------------
@app.route("/api/dashboard_stats")
@login_required
def api_dashboard_stats():
    """Get dashboard statistics"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            
            c.execute("SELECT COUNT(*) FROM port_scans")
            total_port_scans = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM audits")
            total_audits = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM file_integrity")
            total_file_checks = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM network_logs")
            total_network_logs = c.fetchone()[0]
            
            c.execute("SELECT host, timestamp, results FROM port_scans ORDER BY id DESC LIMIT 1")
            recent_port_scan = c.fetchone()
            recent_scan_data = None
            if recent_port_scan:
                results = json.loads(recent_port_scan[2])
                recent_scan_data = {
                    "host": recent_port_scan[0],
                    "timestamp": recent_port_scan[1],
                    "open_ports": len(results)
                }
            
            c.execute("SELECT timestamp FROM audits ORDER BY id DESC LIMIT 1")
            recent_audit = c.fetchone()
            
            c.execute("SELECT timestamp, directory FROM file_integrity ORDER BY id DESC LIMIT 1")
            recent_file_check = c.fetchone()
            
            return jsonify({
                "total_port_scans": total_port_scans,
                "total_audits": total_audits,
                "total_file_checks": total_file_checks,
                "total_network_logs": total_network_logs,
                "recent_port_scan": recent_scan_data,
                "recent_audit": recent_audit[0] if recent_audit else None,
                "recent_file_check": {
                    "timestamp": recent_file_check[0],
                    "directory": recent_file_check[1]
                } if recent_file_check else None
            })
    except Exception as e:
        app.logger.exception("Dashboard stats failed")
        return jsonify({"error": str(e)}), 500

@app.route("/api/network_chart_data")
@login_required
def api_network_chart_data():
    """Get network chart data"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT upload, download, timestamp FROM network_logs ORDER BY id DESC LIMIT 10")
            logs = c.fetchall()
            
            logs.reverse()
            
            uploads = [log[0] for log in logs]
            downloads = [log[1] for log in logs]
            timestamps = [log[2].split(' ')[1] for log in logs]
            
            return jsonify({
                "uploads": uploads,
                "downloads": downloads,
                "timestamps": timestamps
            })
    except Exception as e:
        app.logger.exception("Network chart data failed")
        return jsonify({"error": str(e)}), 500

@app.route("/api/port_scan_chart_data")
@login_required
def api_port_scan_chart_data():
    """Get port scan chart data"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT host, results FROM port_scans ORDER BY id DESC LIMIT 5")
            scans = c.fetchall()
            
            scans.reverse()
            
            hosts = []
            open_ports = []
            
            for scan in scans:
                hosts.append(scan[0])
                results = json.loads(scan[1])
                open_ports.append(len(results))
            
            return jsonify({
                "hosts": hosts,
                "open_ports": open_ports
            })
    except Exception as e:
        app.logger.exception("Port scan chart data failed")
        return jsonify({"error": str(e)}), 500

@app.route("/api/system_perf_chart_data")
@login_required
def api_system_perf_chart_data():
    """Get system performance chart data"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT results, timestamp FROM audits ORDER BY id DESC LIMIT 10")
            audits = c.fetchall()
            
            audits.reverse()
            
            cpu_usage = []
            timestamps = []
            
            for audit in audits:
                data = json.loads(audit[0])
                cpu_str = data.get('cpu_usage', '0%').replace('%', '')
                try:
                    cpu_usage.append(float(cpu_str))
                except:
                    cpu_usage.append(0)
                timestamps.append(audit[1].split(' ')[1])
            
            return jsonify({
                "cpu_usage": cpu_usage,
                "timestamps": timestamps
            })
    except Exception as e:
        app.logger.exception("System performance chart data failed")
        return jsonify({"error": str(e)}), 500

# ---------------- HISTORY / LOGS ----------------
@app.route("/history")
@login_required
def history():
    """History and logs page"""
    app.logger.info(f"History page accessed by user: {session.get('user')}")
    return render_template("history.html")

@app.route("/api/history_data")
@login_required
def api_history_data():
    """Get history data"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            
            # Get port scans
            c.execute("SELECT id, host, start_port, end_port, timestamp, results FROM port_scans ORDER BY id DESC LIMIT 50")
            port_scans = []
            for row in c.fetchall():
                results = json.loads(row[5])
                port_scans.append({
                    "id": row[0],
                    "host": row[1],
                    "start_port": row[2],
                    "end_port": row[3],
                    "timestamp": row[4],
                    "open_ports": len(results)
                })
            
            # Get audits
            c.execute("SELECT id, timestamp, results FROM audits ORDER BY id DESC LIMIT 50")
            audits = []
            for row in c.fetchall():
                audit_data = json.loads(row[2])
                audits.append({
                    "id": row[0],
                    "timestamp": row[1],
                    "os": audit_data.get("os", "Unknown"),
                    "cpu_usage": audit_data.get("cpu_usage", "N/A"),
                    "ram_usage": audit_data.get("ram_usage", "N/A")
                })
            
            # Get file integrity checks
            c.execute("SELECT id, directory, algorithm, timestamp, baseline FROM file_integrity ORDER BY id DESC LIMIT 50")
            file_checks = []
            for row in c.fetchall():
                baseline = json.loads(row[4])
                file_checks.append({
                    "id": row[0],
                    "directory": row[1],
                    "algorithm": row[2],
                    "timestamp": row[3],
                    "files_count": len(baseline)
                })
            
            # Get network logs
            c.execute("SELECT id, upload, download, timestamp FROM network_logs ORDER BY id DESC LIMIT 50")
            network_logs = []
            for row in c.fetchall():
                network_logs.append({
                    "id": row[0],
                    "upload": row[1],
                    "download": row[2],
                    "timestamp": row[3]
                })
            
            return jsonify({
                "port_scans": port_scans,
                "audits": audits,
                "file_checks": file_checks,
                "network_logs": network_logs
            })
    except Exception as e:
        app.logger.exception("History data fetch failed")
        return jsonify({"error": str(e)}), 500

# ---------------- EXPORT FUNCTIONALITY ----------------
@app.route("/export/<report_type>/<format>")
@login_required
@limiter.limit("20 per hour")
def export_report(report_type, format):
    """Export reports to PDF or CSV"""
    try:
        username = session.get("user")
        app.logger.info(f"Export initiated by {username}: {report_type} as {format}")
        
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            
            if format == 'csv':
                return export_csv(c, report_type)
            elif format == 'pdf':
                return export_pdf(c, report_type)
            else:
                flash("Invalid export format", "danger")
                return redirect(url_for('history'))
                
    except Exception as e:
        app.logger.exception("Export failed")
        flash(f"Export failed: {str(e)}", "danger")
        return redirect(url_for('history'))

def export_csv(cursor, report_type):
    """Export data as CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    if report_type == 'port_scans':
        cursor.execute("SELECT host, start_port, end_port, timestamp, results FROM port_scans ORDER BY id DESC")
        writer.writerow(['Host', 'Start Port', 'End Port', 'Open Ports', 'Timestamp'])
        for row in cursor.fetchall():
            results = json.loads(row[4])
            writer.writerow([row[0], row[1], row[2], len(results), row[3]])
        filename = 'port_scans_report.csv'
        
    elif report_type == 'audits':
        cursor.execute("SELECT timestamp, results FROM audits ORDER BY id DESC")
        writer.writerow(['Timestamp', 'OS', 'CPU', 'RAM (GB)', 'RAM Usage', 'CPU Usage'])
        for row in cursor.fetchall():
            data = json.loads(row[1])
            writer.writerow([
                row[0], 
                data.get('os'), 
                data.get('cpu'), 
                data.get('ram'), 
                data.get('ram_usage', 'N/A'), 
                data.get('cpu_usage')
            ])
        filename = 'system_audits_report.csv'
        
    elif report_type == 'file_checks':
        cursor.execute("SELECT directory, algorithm, timestamp, baseline FROM file_integrity ORDER BY id DESC")
        writer.writerow(['Directory', 'Algorithm', 'Files Count', 'Timestamp'])
        for row in cursor.fetchall():
            baseline = json.loads(row[3])
            writer.writerow([row[0], row[1], len(baseline), row[2]])
        filename = 'file_integrity_report.csv'
        
    elif report_type == 'network_logs':
        cursor.execute("SELECT upload, download, timestamp FROM network_logs ORDER BY id DESC")
        writer.writerow(['Upload (KB/s)', 'Download (KB/s)', 'Timestamp'])
        for row in cursor.fetchall():
            writer.writerow([row[0], row[1], row[2]])
        filename = 'network_logs_report.csv'
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

def export_pdf(cursor, report_type):
    """Export data as PDF"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2d3748'),
        spaceAfter=30,
    )
    
    # Add title
    if report_type == 'port_scans':
        title = Paragraph("Port Scans Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        cursor.execute("SELECT host, start_port, end_port, timestamp, results FROM port_scans ORDER BY id DESC LIMIT 50")
        data = [['Host', 'Port Range', 'Open Ports', 'Timestamp']]
        for row in cursor.fetchall():
            results = json.loads(row[4])
            data.append([row[0], f"{row[1]}-{row[2]}", str(len(results)), row[3]])
        filename = 'port_scans_report.pdf'
        
    elif report_type == 'audits':
        title = Paragraph("System Audits Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        cursor.execute("SELECT timestamp, results FROM audits ORDER BY id DESC LIMIT 50")
        data = [['Timestamp', 'OS', 'CPU Usage', 'RAM Usage']]
        for row in cursor.fetchall():
            audit_data = json.loads(row[1])
            data.append([
                row[0], 
                audit_data.get('os', 'N/A'), 
                audit_data.get('cpu_usage', 'N/A'), 
                audit_data.get('ram_usage', 'N/A')
            ])
        filename = 'system_audits_report.pdf'
        
    elif report_type == 'file_checks':
        title = Paragraph("File Integrity Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        cursor.execute("SELECT directory, algorithm, timestamp, baseline FROM file_integrity ORDER BY id DESC LIMIT 50")
        data = [['Directory', 'Algorithm', 'Files', 'Timestamp']]
        for row in cursor.fetchall():
            baseline = json.loads(row[3])
            data.append([row[0], row[1].upper(), str(len(baseline)), row[2]])
        filename = 'file_integrity_report.pdf'
        
    elif report_type == 'network_logs':
        title = Paragraph("Network Logs Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        cursor.execute("SELECT upload, download, timestamp FROM network_logs ORDER BY id DESC LIMIT 50")
        data = [['Upload (KB/s)', 'Download (KB/s)', 'Timestamp']]
        for row in cursor.fetchall():
            data.append([str(row[0]), str(row[1]), row[2]])
        filename = 'network_logs_report.pdf'
    
    # Create table
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4299e1')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')])
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Add footer
    footer = Paragraph(f"Generated on {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Security Toolkit", styles['Normal'])
    elements.append(footer)
    
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )

# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    app.logger.warning(f"404 error: {request.url}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    app.logger.error(f"500 error: {e}")
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    app.logger.warning(f"Rate limit exceeded: {request.remote_addr} - {request.path}")
    return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

# ---------------- MAIN ----------------
if __name__ == "__main__":
    debug_mode = os.getenv('DEBUG', 'false').lower() == 'true'
    app.logger.info(f"Starting Flask app (debug={debug_mode})")
    app.run(debug=debug_mode)