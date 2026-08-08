from flask import  Flask, render_template, redirect, flash, request, session, send_file, jsonify
from ai_detector import AIDetector
from firewall import isolate_main_server, activate_backup_server
from honeypot import activate_honeypot, deactivate_honeypot
from otp_service import send_otp, verify_otp
from report_generator import generate_detailed_report, get_ip_details

from enhancements import start_continuous_simulation, stop_attack_mode

import random
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback_secret_key")

detector = AIDetector()

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "stark_admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "fallback_password")
USER_PHONE = os.environ.get("USER_PHONE", "fallback_phone")

SECURE_KEY = os.environ.get("SECURE_KEY", "fallback_secure_key")

traffic_logs = []
blocked_ips = {}
unblocked_ips = []
simulation_active = False # New state variable
current_slm_decision = None


# 🔐 BLOCK WITH TIME
def block_ip_with_timeout(ip, minutes=5):
    blocked_ips[ip] = time.time() + (minutes * 60)


# 🔄 AUTO UNBLOCK
def is_blocked(ip):
    if ip in blocked_ips:
        if time.time() > blocked_ips[ip]:
            del blocked_ips[ip]
            return False
        return True
    return False


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("locked"):
        flash("🚫 Account locked!", "danger")
        return render_template("login.html")

    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")
        otp_input = request.form.get("otp")

        if 'attempts' not in session:
            session['attempts'] = 0

        if user == ADMIN_USERNAME and pwd == ADMIN_PASSWORD:

            if verify_otp(USER_PHONE, otp_input):
                session['admin'] = True
                session['attempts'] = 0
                
                # Check if it's an AJAX request
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
                    return jsonify({"success": True, "redirect": "/dashboard"})
                
                flash("✅ Login Successful", "success")
                return redirect("/dashboard")
            else:
                session['attempts'] += 1
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
                    return jsonify({"success": False, "message": "❌ Wrong OTP!"})
                flash("❌ Wrong OTP!", "danger")

        else:
            session['attempts'] += 1
            remaining = 3 - session['attempts']

            if remaining <= 0:
                session['locked'] = True
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
                    return jsonify({"success": False, "message": "🚫 Account locked!"})
                flash("🚫 Account locked!", "danger")
            else:
                msg = f"❌ Wrong Password! Attempts left: {remaining}"
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
                    return jsonify({"success": False, "message": msg})
                flash(msg, "warning")

    return render_template("login.html")


# ---------------- SEND OTP ----------------
@app.route("/send_otp")
def send_otp_route():
    send_otp(USER_PHONE)
    return "OTP Sent"


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ---------------- HOME ----------------
@app.route("/")
def index():
    if session.get("admin"):
        return redirect("/dashboard")
    return render_template("landing.html")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect("/login")

    return render_template(
        "dashboard.html",
        logs=traffic_logs[-50:][::-1],
        blocked_ips=blocked_ips,
        unblocked_ips=unblocked_ips,
        simulation_active=simulation_active
    )


# ---------------- UNBLOCKED PAGE ----------------
@app.route("/unblocked_ips")
def show_unblocked_ips():
    if not session.get("admin"):
        return redirect("/login")

    return render_template("unblocked_ips.html", unblocked_ips=unblocked_ips)


# 🌍 IP TRACKING
def get_ip_details(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}")
        data = res.json()

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp")
        }
    except:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "lat": 0,
            "lon": 0,
            "isp": "Unknown"
        }


# 🔥 SIMULATION
def run_simulation_logic():

    ip = random.choice([
        f"45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        f"103.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        f"185.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
        f"23.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
    ])

    count = len(traffic_logs)

    if count < 3:
        traffic = "normal"
    elif count < 5:
        traffic = "heavy"
    else:
        # 🚨 HEAVILY BOOST ATTACK FREQUENCY
        traffic = random.choice(["attack", "attack", "attack", "heavy"])

    global current_slm_decision

    if traffic == "normal":
        current_slm_decision = detector.analyze_event("Normal user browsing activity")
        traffic_logs.append({
            "ip": ip,
            "type": "Normal",
            "status": "Safe",
            "severity": "Low"
        })

    elif traffic == "heavy":
        current_slm_decision = detector.analyze_event("Sudden spike in unusual traffic from unknown IP")
        traffic_logs.append({
            "ip": ip,
            "type": "Heavy Traffic",
            "status": "Monitoring",
            "severity": "Medium"
        })

    elif traffic == "attack":

        attack_map = {
            "Low": ["Port Scanning", "Phishing Attempt", "Information Leakage", "Cookie Theft"],
            "Medium": ["Brute Force Attack", "Credential Stuffing", "Session Hijacking", "API Abuse"],
            "High": ["SQL Injection", "Cross-Site Scripting (XSS)", "MITM Attack", "DNS Spoofing", "Local File Inclusion"],
            "Critical": ["DDoS Attack", "Ransomware Infection", "Zero-Day Exploit", "Data Exfiltration", "Remote Code Execution (RCE)", "System Hijacking", "Unauthorized Privilege Escalation", "Advanced Persistent Threat (APT)"]
        }

        # Weighted selection: CRITICAL AND HIGH BOOSTED SIGNIFICANTLY
        severity_roll = random.random()
        if severity_roll < 0.15:
            severity = "Low"
        elif severity_roll < 0.35:
            severity = "Medium"
        elif severity_roll < 0.75:
            severity = "High"
        else:
            severity = "Critical"

        attack_type = random.choice(attack_map[severity])

        if severity == "Critical":
            current_slm_decision = detector.analyze_event(f"Critical attack detected: {attack_type} from {ip}")
        elif "Brute" in attack_type or "Credential" in attack_type:
            current_slm_decision = detector.analyze_event(f"Multiple failed login attempts from unknown IP: {ip}")
        elif "Scan" in attack_type:
            current_slm_decision = detector.analyze_event(f"Suspicious port scan detected from {ip}")
        else:
            current_slm_decision = detector.analyze_event(f"Malware or attack detected: {attack_type} from {ip}")

        if severity == "Low":
            status = "Monitoring"

        elif severity == "Medium":
            status = "Alert"

        elif severity == "High":
            block_ip_with_timeout(ip, random.randint(5, 15))
            status = "Blocked"

        elif severity == "Critical":
            block_ip_with_timeout(ip, random.randint(15, 25))
            isolate_main_server()
            status = "Critical Response"

        traffic_logs.append({
            "ip": ip,
            "type": attack_type,
            "status": status,
            "severity": severity
        })


# 🔓 UNBLOCK
@app.route("/unblock/<ip>")
def unblock(ip):
    if not session.get("admin"):
        return redirect("/login")

    # Force string for dict key safety
    target_ip = str(ip).strip()

    # Remove from blocked dict if present
    if target_ip in blocked_ips:
        del blocked_ips[target_ip]

    # Find the most recent incident for this IP to preserve metadata
    log_data = None
    for log in reversed(traffic_logs):
        if log["ip"] == target_ip:
            log_data = log
            break

    # If no historical record found (e.g. after a clear), create a generic signature
    if not log_data:
        log_data = {
            "type": "External Override",
            "severity": "Unknown"
        }

    # Record in the Unblocked Directory (Avoid duplicates)
    is_already_listed = any(item["ip"] == target_ip for item in unblocked_ips)
    if not is_already_listed:
        unblocked_ips.append({
            "ip": target_ip,
            "type": log_data.get("type", "Unknown"),
            "status": "Authorized",
            "severity": log_data.get("severity", "Low"),
            "timestamp": time.time()
        })

    flash(f"🔓 Node {target_ip} authorized for manual override by Stark Protocol.", "success")
    return redirect("/unblocked_ips") # Redirect to the unblocked list directly to show it worked


# 🔒 RE-BLOCK
@app.route("/reblock/<ip>")
def reblock(ip):
    if not session.get("admin"):
        return redirect("/login")
    
    # 1. Add back to blocked_ips with timeout
    block_ip_with_timeout(ip, minutes=15)
    
    # 2. Remove from unblocked_ips list
    global unblocked_ips
    unblocked_ips = [item for item in unblocked_ips if item["ip"] != ip]
    
    # 3. Add to traffic logs
    traffic_logs.append({
        "ip": ip,
        "type": "Manual Re-block",
        "status": "Blocked",
        "severity": "High"
    })
    
    flash(f"🔒 {ip} has been manually re-blocked.", "danger")
    return redirect("/unblocked_ips")


# 🔒 MANUAL BLOCK FROM DASHBOARD
@app.route("/block_manual/<ip>")
def block_manual(ip):
    if not session.get("admin"):
        return redirect("/login")
    
    block_ip_with_timeout(ip, minutes=30)
    
    traffic_logs.append({
        "ip": ip,
        "type": "Manual Block",
        "status": "Blocked",
        "severity": "High"
    })
    
    flash(f"🔒 {ip} has been manually blocked from the dashboard.", "danger")
    return redirect("/dashboard")


# 🧹 QUICK CLEAR
@app.route("/clear_dashboard")
def clear_dashboard():
    global current_slm_decision
    if not session.get("admin"):
        return redirect("/login")
    
    traffic_logs.clear()
    blocked_ips.clear()
    unblocked_ips.clear()
    current_slm_decision = None
    flash("🧹 Dashboard Cleared Successfuly. Starting fresh.", "success")
    return redirect("/dashboard")


# 📄 REPORT
@app.route("/generate_report")
def generate_report():
    if not session.get("admin"):
        return redirect("/login")

    file = generate_detailed_report(traffic_logs)
    return send_file(file, as_attachment=True)


# 📄 REPORT BY IP
@app.route("/generate_report_ip")
def generate_report_ip():
    if not session.get("admin"):
        return redirect("/login")

    ip = request.args.get("ip")

    if ip:
        ip = ip.strip()

    filtered_logs = [log for log in traffic_logs if log["ip"] == ip]

    if not filtered_logs:
        flash("No data found for this IP", "warning")
        return redirect("/dashboard")

    file = generate_detailed_report(filtered_logs)
    return send_file(file, as_attachment=True)


# ---------------- START ----------------
@app.route("/simulate")
def simulate():
    if not session.get("admin"):
        return redirect("/login")

    global simulation_active
    simulation_active = True
    start_continuous_simulation(app, run_simulation_logic)
    flash("⚡ Traffic Started", "info")
    return redirect("/dashboard")


# ---------------- STOP ----------------
@app.route("/stop_attack")
def stop_attack():
    global simulation_active
    simulation_active = False
    stop_attack_mode()
    flash("🛑 Stopped", "info")
    return redirect("/dashboard")


# ---------------- RESET ----------------
@app.route("/reset")
def reset():
    if not session.get("admin"):
        return redirect("/login")

    key = request.args.get("key")
    if key != SECURE_KEY:
        flash("❌ Invalid Secure Key. Reset aborted.", "danger")
        return redirect("/dashboard")

    stop_attack_mode() 
    global traffic_logs, blocked_ips, unblocked_ips
    traffic_logs.clear()
    blocked_ips.clear()
    unblocked_ips.clear()
    
    session.clear() 
    flash("♻️ System Reset Successfully. All data cleared.", "success")
    return redirect("/")


# ---------------- IDLE TIMEOUT ----------------
@app.route("/idle_timeout")
def idle_timeout():
    session.clear() 
    flash("🕒 Session timed out due to inactivity.", "warning")
    return redirect("/")



# 🌍 TRACK
@app.route("/track_ip/<ip>")
def track_ip(ip):
    if not session.get("admin"):
        return redirect("/dashboard")

    info = get_ip_details(ip)
    info["ip"] = ip

    return render_template("track_ip.html", info=info)


# 🔐 DEACTIVATE
@app.route("/deactivate", methods=["POST"])
def deactivate():
    key = request.form.get("key")
    otp = request.form.get("otp")

    if key == SECURE_KEY and verify_otp(USER_PHONE, otp):
        deactivate_honeypot()
        flash("🛑 Honeypot Deactivated!", "success")
    else:
        flash("❌ Invalid Key or OTP!", "danger")

    return redirect("/dashboard")


# 🔍 IP FORENSICS API
@app.route("/api/ip_forensics/<ip>")
def ip_forensics(ip):
    if not session.get("admin"):
        return jsonify({"error": "Unauthorized"}), 401
    
    details = get_ip_details(ip)
    # Add a google maps link for the frontend
    if details['lat'] != "Unknown" and details['lon'] != "Unknown":
        details['map_url'] = f"https://www.google.com/maps?q={details['lat']},{details['lon']}"
    else:
        details['map_url'] = "#"
        
    return jsonify(details)

# 🧠 SLM STATUS API
@app.route("/api/slm_status")
def slm_status():
    if not session.get("admin"):
        return jsonify({"error": "unauthorized"}), 401
    
    if not current_slm_decision:
        return jsonify({
            "event": "System idle",
            "risk_level": "LOW",
            "confidence": 100,
            "action": "Allow",
            "reason": "Simulation not started",
            "timestamp": "AUTO",
            "ui": {"color": "gray", "status_text": "Offline"},
            "requests_per_sec": 0,
            "failed_logins": 0,
            "anomaly_score": 0,
            "analyzed_count": len(traffic_logs)
        })
        
    # Append simulated numeric stats based on the string logic for the UI to display
    rl = current_slm_decision.get("risk_level", "LOW")
    if rl == "HIGH":
        current_slm_decision["requests_per_sec"] = random.randint(90, 300)
        current_slm_decision["failed_logins"] = random.randint(5, 30)
        current_slm_decision["anomaly_score"] = round(random.uniform(-0.6, -0.4), 4)
    elif rl == "MEDIUM":
        current_slm_decision["requests_per_sec"] = random.randint(50, 80)
        current_slm_decision["failed_logins"] = random.randint(2, 4)
        current_slm_decision["anomaly_score"] = round(random.uniform(-0.3, -0.1), 4)
    else:
        current_slm_decision["requests_per_sec"] = random.randint(18, 40)
        current_slm_decision["failed_logins"] = random.randint(0, 2)
        current_slm_decision["anomaly_score"] = round(random.uniform(-0.1, 0.1), 4)
        
    current_slm_decision["analyzed_count"] = len(traffic_logs)
    return jsonify(current_slm_decision)

# 📊 UNIFIED DASHBOARD DATA API
@app.route("/api/dashboard_data")
@app.route("/api/dashboard_data")
def dashboard_data():
    if not session.get("admin"):
        return jsonify({"error": "unauthorized"}), 401
    
    query = request.args.get('q', '').lower()
    
    # Calculate global stats
    crit_count = len([l for l in traffic_logs if l.get('severity') == 'Critical'])
    high_count = len([l for l in traffic_logs if l.get('severity') == 'High'])
    
    # Filtering logic
    filtered_logs = traffic_logs
    if query:
        filtered_logs = [
            l for l in traffic_logs 
            if query in l.get('ip', '').lower() 
            or query in l.get('type', '').lower() 
            or query in l.get('status', '').lower() 
            or query in l.get('severity', '').lower()
        ]
    
    return jsonify({
        "logs": filtered_logs[-50:][::-1], # Last 50 relevant, newest first
        "stats": {
            "total_logs": len(traffic_logs),
            "critical_attacks": crit_count,
            "high_attacks": high_count,
            "blocked_ips_count": len(blocked_ips),
            "simulation_active": simulation_active
        },
        "blocked_ips": list(blocked_ips),
        "slm_active": current_slm_decision is not None,
        "is_filtered": bool(query)
    })

@app.context_processor
def inject_time():
    return dict(time=time.time)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)