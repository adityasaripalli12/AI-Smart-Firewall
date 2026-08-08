honeypot_active = False

def activate_honeypot(ip):
    global honeypot_active
    honeypot_active = True
    print(f"[HONEYPOT] Activated for attacker IP: {ip}")

def deactivate_honeypot():
    global honeypot_active
    if honeypot_active:
        honeypot_active = False
        print("[HONEYPOT] Deactivated")
    else:
        print("[HONEYPOT] Already OFF")