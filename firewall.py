from datetime import datetime, timedelta

# ✅ NEW: Store blocked IPs with metadata
blocked_ips = {}

def isolate_main_server():
    print("Main server isolated")

def activate_backup_server():
    print("Backup server activated")

# ✅ EXISTING FUNCTION (UNCHANGED)
def block_ip(ip):
    print("Blocked IP:", ip)

    with open("logs/attacks.txt", "a") as f:
        f.write("Blocked IP: " + ip + "\n")

# ✅ NEW: ADVANCED BLOCK (wraps your existing function)
def smart_block_ip(ip, reason="Suspicious Activity", duration_minutes=5):
    # Call your original function
    block_ip(ip)

    # Add new tracking system
    blocked_ips[ip] = {
        "blocked_at": datetime.now(),
        "unblock_at": datetime.now() + timedelta(minutes=duration_minutes),
        "reason": reason,
        "status": "blocked"
    }

# ✅ NEW: UNBLOCK FUNCTION
def unblock_ip(ip):
    if ip in blocked_ips:
        blocked_ips[ip]["status"] = "unblocked"
        print(f"{ip} unblocked")

# ✅ NEW: FALSE POSITIVE HANDLING
def mark_false_positive(ip):
    if ip in blocked_ips:
        blocked_ips[ip]["status"] = "false_positive"
        print(f"{ip} marked as false positive")

# ✅ NEW: AUTO UNBLOCK SYSTEM
def auto_unblock():
    now = datetime.now()
    for ip in list(blocked_ips.keys()):
        if blocked_ips[ip]["status"] == "blocked":
            if blocked_ips[ip]["unblock_at"] <= now:
                unblock_ip(ip)