from flask import Flask, render_template, redirect, send_file, request, session, url_for, flash, jsonify
from parser.log_parser import LogParser
from reports.report_generator import ReportGenerator
from detection.brute_force import BruteForceDetector
from detection.admin_login import AdminLoginDetector
from detection.sql_injection import SQLInjectionDetector
from detection.suspicious_ip import SuspiciousIPDetector
import os
import re
from collections import Counter
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from alerts.alert_manager import AlertManager
from config import Config
from database import init_db, get_user, create_user
from packet_capturer import PacketCapturer
from ml.predictor import predict_log

app = Flask(__name__)
app.config.from_object(Config)

# Initialize user database
init_db()

# Initialize packet capturer thread
capturer = PacketCapturer()
if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    capturer.start()

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
        
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = get_user(username)
        if user and check_password_hash(user["password"], password):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid Username or Password."
            
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
        
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        
        if not username or not password:
            error = "Username and Password are required."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            hashed_pw = generate_password_hash(password)
            if create_user(username, hashed_pw):
                success = "Account created successfully! You can now log in."
            else:
                error = "Username already exists."
                
    return render_template("register.html", error=error, success=success)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():

    # ----------------------------
    # Read Logs
    # ----------------------------

    log_file = session.get("log_file", "log/sample_log.txt")
    parser = LogParser(log_file)

    logs = parser.read_logs()

    total_logs = parser.total_logs()

    # ----------------------------
    # Detection
    # ----------------------------

    brute_detector = BruteForceDetector()

    admin_detector = AdminLoginDetector()

    sql_detector = SQLInjectionDetector()

    ip_detector = SuspiciousIPDetector()

    brute_alerts = brute_detector.detect(
        parser.failed_login_logs()
    )

    admin_alerts = admin_detector.detect(
        parser.admin_login_logs()
    )

    sql_alerts = sql_detector.detect(
        logs
    )

    ip_alerts = ip_detector.detect(
        logs
    )

    # ----------------------------
    # Alert Manager
    # ----------------------------

    manager = AlertManager()

    manager.clear_alerts()

    all_alerts = []

    for alert in brute_alerts:
        message = f"[CRITICAL] {alert['type']} - {alert['message']}"
        manager.save_alert(message)
        all_alerts.append(message)

    for alert in admin_alerts:
        message = f"[MEDIUM] {alert['type']} - {alert['message']}"
        manager.save_alert(message)
        all_alerts.append(message)

    for alert in sql_alerts:
        message = f"[CRITICAL] {alert['type']} - {alert['message']}"
        manager.save_alert(message)
        all_alerts.append(message)

    for alert in ip_alerts:
        message = f"[HIGH] {alert['type']} - {alert['message']}"
        manager.save_alert(message)
        all_alerts.append(message)
# ----------------------------
# Risk Score
# ----------------------------

    # ----------------------------
    # Risk Score
    # ----------------------------

    risk_score = 0

    risk_score += len(brute_alerts) * 20
    risk_score += len(sql_alerts) * 40
    risk_score += len(ip_alerts) * 25
    risk_score += len(admin_alerts) * 15

    if risk_score > 100:
        risk_score = 100

    if risk_score >= 80:
        threat_level = "CRITICAL"

    elif risk_score >= 60:
        threat_level = "HIGH"

    elif risk_score >= 30:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"

       # ----------------------------
    # Top Attacker IPs
    # ----------------------------

    ip_counter = Counter()

    for log in logs:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)

        for ip in ips:
            ip_counter[ip] += 1

    top_ips = []

    for ip, count in ip_counter.most_common(10):
        top_ips.append({
            "address": ip,
            "count": count
        })

    # ----------------------------
    # Machine Learning Prediction
    # ----------------------------

    ml_prediction = predict_log(
        failed_login=len(parser.failed_login_logs()),
        sql_injection=len(sql_alerts),
        admin_login=len(admin_alerts),
        suspicious_ip=len(ip_alerts),
        requests=total_logs
    )

    # ----------------------------
    # Return Dashboard
    # ----------------------------

    return render_template(
        "dashboard.html",

        total_logs=total_logs,
        total_alerts=manager.total_alerts(),

        brute_force=len(brute_alerts),
        admin_login=len(admin_alerts),
        sql_injection=len(sql_alerts),
        suspicious_ip=len(ip_alerts),

        alerts=manager.get_alerts(),

        risk_score=risk_score,
        threat_level=threat_level,

        top_ips=top_ips,
        ml_prediction=ml_prediction
    )
@app.route("/log")
@login_required
def logs():

    log_file = session.get("log_file", "log/sample_log.txt")
    print("Current Log File:", log_file)
    parser = LogParser(log_file)

    logs = parser.read_logs()

    return render_template(
        "logs.html",
        logs=logs
    )

@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():

    if request.method=="POST":

        file=request.files["logfile"]

        if file:

            filename=secure_filename(file.filename)

            filepath=os.path.join(
                app.config["UPLOAD_FOLDER"],
                filename
            )

            file.save(filepath)
            
            # Store in session so it persists for this session's dashboard and log views
            session["log_file"] = filepath

            return redirect(url_for("dashboard"))

    return render_template("upload.html")


@app.route("/alerts")
@login_required
def alerts():

    manager = AlertManager()
    alerts_list = manager.get_alerts()
    
    # Calculate severity counts
    critical_count = sum(1 for a in alerts_list if "[CRITICAL]" in a)
    high_count = sum(1 for a in alerts_list if "[HIGH]" in a)
    medium_count = sum(1 for a in alerts_list if "[MEDIUM]" in a)

    return render_template(

        "alerts.html",

        alerts=alerts_list,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count

    )

@app.route("/clear_alerts")
@login_required
def clear_alerts():

    manager = AlertManager()

    manager.clear_alerts()

    return redirect(url_for("alerts"))


@app.route("/reports")
@login_required
def reports():

    manager = AlertManager()

    alerts = manager.get_alerts()

    report = ReportGenerator()

    report.generate_daily_report(alerts)

    return render_template(

        "reports.html",

        alerts=alerts,

        total=len(alerts)

    )
@app.route("/incident")
@login_required
def incident():
    return render_template("incident.html")
@app.route("/block_ip", methods=["POST"])
@login_required
def block_ip():

    ip = request.form.get("ip")

    if ip:

        with open("blocked_ips/blocked_ips.txt", "a") as f:
            f.write(ip + "\n")

        flash(f"{ip} blocked successfully.", "success")

    return redirect(url_for("incident"))
@app.route("/isolate_host", methods=["POST"])
@login_required
def isolate_host():

    flash("Host isolated successfully.", "success")

    return redirect(url_for("incident"))
@app.route("/generate_incident_report", methods=["POST"])
@login_required
def generate_incident_report():

    report_path = "reports/incident_report.txt"

    with open(report_path, "w") as f:
        f.write("SOC Incident Report\n")
        f.write("=========================\n\n")
        f.write("Threats Detected:\n")
        f.write("- SQL Injection\n")
        f.write("- Brute Force\n")
        f.write("- Suspicious IP\n")
        f.write("- Admin Login\n\n")
        f.write("Recommended Actions:\n")
        f.write("• Block malicious IPs\n")
        f.write("• Isolate affected host\n")
        f.write("• Review server logs\n")
        f.write("• Reset compromised accounts\n")

    return send_file(report_path, as_attachment=True)

@app.route("/download_report")
@login_required
def download_report():

    return send_file(

        "reports/daily_report.txt",

        as_attachment=True

    )


@app.route("/live")
@login_required
def live():
    return render_template("live.html")


@app.route("/api/live_packets")
@login_required
def api_live_packets():
    return jsonify({
        "packets": capturer.get_packets(),
        "metrics": capturer.get_metrics()
    })


@app.route("/api/toggle_capture", methods=["POST"])
@login_required
def api_toggle_capture():
    if capturer.running:
        capturer.stop()
    else:
        capturer.start()
    return jsonify({
        "status": "success",
        "running": capturer.running
    })


@app.route("/api/clear_capture", methods=["POST"])
@login_required
def api_clear_capture():
    capturer.clear()
    return jsonify({
        "status": "success"
    })


if __name__ == "__main__":
    app.run(debug=True)