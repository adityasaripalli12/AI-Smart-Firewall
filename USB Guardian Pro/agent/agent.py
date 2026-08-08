import os
import sys
import time
import ctypes
import string
import requests
import socket
from datetime import datetime
from PIL import Image, ImageGrab, ImageDraw

# Try importing OpenCV for real webcam capture. Fall back gracefully if missing or no camera.
try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

# Backend API Configuration
SERVER_URL = "http://127.0.0.1:5000"

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def set_usbstor_state(enabled):
    """
    Modifies Windows Registry to enable (3) or disable (4) USB storage devices.
    Requires administrator privileges to succeed.
    """
    if sys.platform != 'win32':
        print("[Agent] USBSTOR policy skipped: Non-Windows platform.")
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
        value = 3 if enabled else 4
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        print(f"\n⚙️ [Policy Update] Windows USBSTOR storage devices set to: {'ENABLED (Ports Open)' if enabled else 'DISABLED (Ports Locked)'}")
        return True
    except PermissionError:
        print("\n🚨 [Security Alert] Failed to apply USBSTOR policy: Access Denied.")
        print("👉 Please run this Agent script as Administrator (Right-Click -> Run as Administrator) to physically lock/unlock USB ports.")
        return False
    except Exception as e:
        print(f"\n⚠️ [Agent] Error applying USBSTOR registry policy: {e}")
        return False

connected_usbs = {}
last_registry_state = None

def start_lockdown_poller(username):
    """
    Starts a background thread that polls the Flask server for global lockdown status
    and currently connected USB devices. Automatically locks/unlocks ports.
    """
    import threading
    def poller_loop():
        global connected_usbs, last_registry_state
        while True:
            try:
                time.sleep(3)
                # 1. Check Global Lockdown status
                res = requests.get(f"{SERVER_URL}/api/lockdown_status", timeout=3)
                is_lockdown = False
                if res.ok:
                    is_lockdown = res.json().get('lockdown_active', False)
                
                # 2. Check each connected USB status
                any_blocked_or_pending = False
                for serial, info in list(connected_usbs.items()):
                    status_res = check_usb_signature(serial, info['device_name'], "0951", "1666", username)
                    current_status = status_res.get('status', 'pending')
                    
                    # Status transition notifications
                    if info['status'] != current_status:
                        if current_status == 'allowed':
                            print(f"\n🟢 [Agent] Whitelist APPROVED for USB (S/N: {serial})! Enabling ports...")
                        elif current_status == 'blocked':
                            print(f"\n🔴 [Agent] Access BLOCKED/REJECTED for USB (S/N: {serial})! Disabling ports...")
                        info['status'] = current_status
                        
                    if current_status in ['blocked', 'pending']:
                        any_blocked_or_pending = True
                        
                # 3. Enforce policy
                # Enable ports ONLY if lockdown is OFF and NO blocked/pending devices are inserted.
                should_enable = not (is_lockdown or any_blocked_or_pending)
                
                if last_registry_state != should_enable:
                    set_usbstor_state(should_enable)
                    last_registry_state = should_enable
                    
            except Exception:
                pass

    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()

# --- CORE AGENT UTILITIES ---

def capture_screenshot(filepath):
    """
    Captures a screenshot of the endpoint and saves it as a JPEG.
    """
    try:
        screenshot = ImageGrab.grab()
        screenshot.convert('RGB').save(filepath, "JPEG", quality=80)
        print(f"[Agent] Screenshot saved successfully: {filepath}")
        return True
    except Exception as e:
        print(f"[Agent] Failed to capture screenshot: {e}")
        # Generate a mock screenshot image using Pillow if native capture fails
        try:
            img = Image.new('RGB', (640, 360), color=(30, 30, 45))
            draw = ImageDraw.Draw(img)
            draw.rectangle([(10, 10), (630, 350)], outline=(255, 62, 62), width=3)
            draw.text((40, 40), f"SCREENSHOT FAILED OR PERMISSION DENIED\n\nTimestamp: {datetime.now()}\nHost: {socket.gethostname()}", fill=(255, 255, 255))
            img.save(filepath, "JPEG")
            return True
        except Exception:
            return False

def capture_webcam(filepath):
    """
    Captures a webcam photo of the user at the endpoint.
    Falls back to a programmatically drawn silhouette if camera is missing or OpenCV is disabled.
    """
    if HAS_OPENCV:
        try:
            cam = cv2.VideoCapture(0)
            if cam.isOpened():
                # Let camera adjust auto exposure
                time.sleep(0.3)
                ret, frame = cam.read()
                if ret:
                    cv2.imwrite(filepath, frame)
                    cam.release()
                    print(f"[Agent] Webcam snapshot saved: {filepath}")
                    return True
            cam.release()
        except Exception as e:
            print(f"[Agent] Camera hardware access failed: {e}")
            
    # Fallback: Draw a digital user silhouette frame
    try:
        img = Image.new('RGB', (640, 480), color=(10, 15, 25))
        draw = ImageDraw.Draw(img)
        # Background Grid lines
        for x in range(0, 640, 40): draw.line([(x, 0), (x, 480)], fill=(20, 30, 50))
        for y in range(0, 480, 40): draw.line([(0, y), (640, y)], fill=(20, 30, 50))
        # Draw camera HUD target
        draw.ellipse([(170, 90), (470, 390)], outline=(0, 255, 136), width=2)
        # Draw head silhouette
        draw.ellipse([(260, 130), (380, 250)], fill=(0, 210, 255))
        # Draw body shoulder silhouette
        draw.ellipse([(200, 270), (440, 450)], fill=(0, 210, 255))
        # Text label overlay
        draw.text((20, 20), "HUD ENDPOINT CAM - DETECTOR ACTIVE", fill=(0, 255, 136))
        draw.text((20, 440), f"Camera Status: SIMULATED SHIELD | {datetime.now()}", fill=(0, 210, 255))
        
        img.save(filepath, "JPEG")
        print(f"[Agent] Generated simulated webcam image: {filepath}")
        return True
    except Exception as e:
        print(f"[Agent] Failed to create mock webcam file: {e}")
        return False

def scan_files_on_drive(drive_path, keywords):
    """
    Recursively scans file names on a drive letter looking for sensitive keywords.
    Returns lists of found files.
    """
    found_files = []
    try:
        for root, dirs, files in os.walk(drive_path):
            # Limit depth of recursive scanning for safety
            if root.count(os.sep) - drive_path.count(os.sep) > 3:
                del dirs[:] # don't descend further
                
            for file in files:
                for kw in keywords:
                    if kw.lower() in file.lower():
                        full_path = os.path.join(root, file)
                        found_files.append(full_path)
                        break
    except Exception as e:
        print(f"[Agent] Disk scanning warning: {e}")
    return found_files

# --- WINDOWS HARDWARE MONITORING ---

def get_windows_removable_drives():
    """
    Queries active drive letters and checks if they are marked removable.
    Uses kernel32 windows DLL bindings.
    """
    drives = []
    if sys.platform != 'win32':
        return drives
        
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive_path = f"{letter}:\\"
                # Drive Type 2 = Removable Drive (USB Flash, etc.)
                if ctypes.windll.kernel32.GetDriveTypeW(drive_path) == 2:
                    drives.append(letter)
            bitmask >>= 1
    except Exception as e:
        print(f"[Agent] Failed logical drives count check: {e}")
    return drives

def get_windows_drive_serial(drive_letter):
    """
    Gets volume serial number for a specific drive letter.
    """
    if sys.platform != 'win32':
        return "UNKNOWN-OS-SERIAL"
        
    try:
        volumeNameBuffer = ctypes.create_unicode_buffer(1024)
        fileSystemNameBuffer = ctypes.create_unicode_buffer(1024)
        serial_number = ctypes.c_ulong(0)
        maxComponentLength = ctypes.c_ulong(0)
        fileSystemFlags = ctypes.c_ulong(0)
        
        res = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(f"{drive_letter}:\\"),
            volumeNameBuffer,
            1024,
            ctypes.byref(serial_number),
            ctypes.byref(maxComponentLength),
            ctypes.byref(fileSystemFlags),
            fileSystemNameBuffer,
            1024
        )
        
        if res:
            return f"USB-VOL-{serial_number.value}"
        else:
            return f"USB-VOL-RAW-{drive_letter}"
    except Exception:
        return f"USB-VOL-ERR-{drive_letter}"

# --- BACKEND API COMMUNICATIONS ---

def check_usb_signature(serial, device_name, vid, pid, username):
    """
    Queries backend whitelists for a USB.
    """
    url = f"{SERVER_URL}/api/check_status"
    payload = {
        "serial_number": serial,
        "device_name": device_name,
        "vendor_id": vid,
        "product_id": pid,
        "username": username
    }
    try:
        res = requests.post(url, json=payload, timeout=5)
        if res.ok:
            return res.json()
    except Exception as e:
        print(f"[Agent] Connection error checking whitelists: {e}")
    return {"status": "pending", "reason": "Server offline, default pending protection."}

def report_threat_event(username, serial, action, details, severity, risk_score):
    """
    Sends log event details to database.
    """
    url = f"{SERVER_URL}/api/report_event"
    payload = {
        "username": username,
        "serial_number": serial,
        "action": action,
        "details": details,
        "severity": severity,
        "risk_score": risk_score
    }
    try:
        res = requests.post(url, json=payload, timeout=5)
        if res.ok:
            return res.json().get('log_id')
    except Exception as e:
        print(f"[Agent] Connection error reporting event: {e}")
    return None

def upload_capture_files(log_id, serial, username, screenshot_path=None, webcam_path=None):
    """
    Uploads screenshot and webcam images to Flask API.
    """
    url = f"{SERVER_URL}/api/upload_capture"
    data = {
        "log_id": log_id,
        "serial_number": serial,
        "username": username
    }
    files = {}
    
    if screenshot_path and os.path.exists(screenshot_path):
        files['screenshot'] = open(screenshot_path, 'rb')
    if webcam_path and os.path.exists(webcam_path):
        files['webcam'] = open(webcam_path, 'rb')
        
    if not files:
        return False
        
    try:
        res = requests.post(url, data=data, files=files, timeout=15)
        # Close handles
        for f in files.values():
            f.close()
        return res.ok
    except Exception as e:
        print(f"[Agent] Connection error uploading captures: {e}")
        return False

# --- AGENT OPERATION MODES ---

def run_hardware_listener(username):
    """
    Enters a background loop monitoring physical drives insertions (Windows only).
    """
    print(f"\n[Agent] Starting hardware listener loop on machine '{socket.gethostname()}'...")
    print(f"[Agent] Mapping connections to Employee: {username}")
    print("[Agent] Listening for USB connections. Press Ctrl+C to exit.")
    
    seen_drives = set(get_windows_removable_drives())
    
    keywords = ["password", "confidential", "ssn", "secret", "cvv"]
    
    while True:
        try:
            time.sleep(2)
            current_drives = set(get_windows_removable_drives())
            
            # 1. Detect drive insertions
            new_drives = current_drives - seen_drives
            for drive in new_drives:
                drive_path = f"{drive}:\\"
                serial = get_windows_drive_serial(drive)
                device_name = f"Removable Volume ({drive}:)"
                
                print(f"\n🔔 [Agent] Removable USB Drive connected at {drive_path} (S/N: {serial})")
                
                # Check backend whitelist status
                status_res = check_usb_signature(serial, device_name, "0951", "1666", username)
                status = status_res.get('status', 'pending')
                
                # Add to local connected dict
                connected_usbs[serial] = {'status': status, 'device_name': device_name, 'drive': drive}
                
                print(f"[Agent] Whitelist status: {status.upper()}")
                
                if status == 'blocked':
                    print("🔴 [Agent] ACCESS DENIED: Device is blacklisted. Triggering containment.")
                    # Instantly lock ports
                    set_usbstor_state(False)
                    
                    scr_file = "scr_temp.jpg"
                    cam_file = "cam_temp.jpg"
                    capture_screenshot(scr_file)
                    capture_webcam(cam_file)
                    
                    log_id = report_threat_event(
                        username=username,
                        serial=serial,
                        action="USB_BLOCKED",
                        details=f"Block Alert: Blacklisted USB Device (S/N: {serial}) connected at drive {drive}:. Threat quarantined.",
                        severity="critical",
                        risk_score=90
                    )
                    
                    upload_capture_files(log_id, serial, username, scr_file, cam_file)
                    
                    # Clean temp files
                    for f in [scr_file, cam_file]:
                        if os.path.exists(f): os.remove(f)
                        
                elif status == 'pending':
                    print("🟡 [Agent] WARNING: Unregistered USB connected. Initiating file scan...")
                    # Instantly lock ports until approved
                    set_usbstor_state(False)
                    
                    # Scan for sensitive content files
                    hits = scan_files_on_drive(drive_path, keywords)
                    
                    if hits:
                        print(f"⚠️ [Agent] Sensitive files detected ({len(hits)} hits). Capturing desktop screenshot...")
                        scr_file = "scr_temp.jpg"
                        capture_screenshot(scr_file)
                        
                        detail_msg = f"DLP Alert: Unregistered USB scanned at drive {drive}:. Found {len(hits)} sensitive file hits. Matches: {', '.join([os.path.basename(h) for h in hits[:3]])}"
                        log_id = report_threat_event(
                            username=username,
                            serial=serial,
                            action="FILE_SCAN_ALERT",
                            details=detail_msg,
                            severity="warning",
                            risk_score=45
                        )
                        
                        upload_capture_files(log_id, serial, username, screenshot_path=scr_file)
                        if os.path.exists(scr_file): os.remove(scr_file)
                    else:
                        print("🟢 [Agent] Disk scan completed. No keywords found. Drive logged.")
                        report_threat_event(
                            username=username,
                            serial=serial,
                            action="USB_INSERT",
                            details=f"Audit Log: Unregistered USB (S/N: {serial}) connection logged at drive {drive}:. Disk clean.",
                            severity="info",
                            risk_score=5
                        )
                        
                else: # allowed
                    print("🟢 [Agent] Access Approved: Whitelisted signature verified.")
                    report_threat_event(
                        username=username,
                        serial=serial,
                        action="USB_INSERT",
                        details=f"Audit Log: Whitelisted USB (S/N: {serial}) connection logged at drive {drive}:.",
                        severity="info",
                        risk_score=0
                    )
                    
            # 2. Detect drive removals
            removed_drives = seen_drives - current_drives
            for drive in removed_drives:
                print(f"\n🔕 [Agent] Removable USB Drive removed from slot {drive}:")
                
                # Remove from local connected dict
                removed_serials = [s for s, info in connected_usbs.items() if info['drive'] == drive]
                for s in removed_serials:
                    connected_usbs.pop(s, None)
                    
                report_threat_event(
                    username=username,
                    serial=f"RAW-VOL-{drive}",
                    action="USB_REMOVE",
                    details=f"Audit Log: Removable drive slot {drive}: disconnected.",
                    severity="info",
                    risk_score=0
                )
                
            seen_drives = current_drives
            
        except KeyboardInterrupt:
            print("\n[Agent] Hardware listener terminated.")
            break
        except Exception as e:
            print(f"[Agent] Loop exception: {e}")
            time.sleep(5)

def run_interactive_simulator(username):
    """
    Renders terminal CLI interface simulating security threat vectors.
    """
    while True:
        print("\n=======================================================")
        print("          USB GUARDIAN PRO - AGENT SIMULATOR           ")
        print("=======================================================")
        print(f"Mapped Employee: {username}")
        print(f"Local Host IP:   {get_ip_address()}")
        print("-------------------------------------------------------")
        print("1. Simulate USB Insertion [ Whitelisted / Approved ]")
        print("2. Simulate USB Insertion [ Unregistered Drive + DLP Hits ]")
        print("3. Simulate USB Insertion [ Banned BadUSB Rubber Ducky ]")
        print("4. Simulate USB Removal")
        print("5. Exit Simulator")
        print("=======================================================")
        
        choice = input("Select scenario node (1-5): ").strip()
        
        if choice == '1':
            serial = "USBG-SEC-2342"
            name = "Kingston DataTraveler"
            print(f"\n[Sim] Initiating Whitelisted USB simulation (S/N: {serial})...")
            
            res = check_usb_signature(serial, name, "0951", "1666", username)
            print(f"[Sim] Server response: Whitelist status is {res.get('status', 'pending').upper()}")
            
            log_id = report_threat_event(
                username=username,
                serial=serial,
                action="USB_INSERT",
                details=f"Audit Log: Simulated approved USB {name} (S/N: {serial}) connected.",
                severity="info",
                risk_score=0
            )
            print(f"[Sim] Insertion event logged. Log ID: {log_id}")
            
        elif choice == '2':
            serial = "UNREG-DRIVE-99"
            name = "Generic Backup Flash"
            print(f"\n[Sim] Initiating Unregistered drive simulation (S/N: {serial})...")
            
            res = check_usb_signature(serial, name, "0aa5", "3c21", username)
            print(f"[Sim] Server response: Status is {res.get('status', 'pending').upper()}")
            
            # DLP Sensitive hit
            scr_file = "screenshot_temp.jpg"
            print("[Sim] Simulating sensitive files detection. Triggering screen capture...")
            capture_screenshot(scr_file)
            
            log_id = report_threat_event(
                username=username,
                serial=serial,
                action="FILE_SCAN",
                details=f"DLP Alert: Simulated unregistered USB connected. Found restricted files: passwords.txt, secret_keys.pem.",
                severity="warning",
                risk_score=45
            )
            print(f"[Sim] Warning event logged (Log ID: {log_id}). Uploading screen capture...")
            
            uploaded = upload_capture_files(log_id, serial, username, screenshot_path=scr_file)
            print(f"[Sim] Capture files uploaded: {uploaded}")
            
            if os.path.exists(scr_file): os.remove(scr_file)
            
        elif choice == '3':
            serial = "BADUSB-666"
            name = "Rubber Ducky Payload"
            print(f"\n[Sim] Initiating Malicious Rubber Ducky intrusion simulation (S/N: {serial})...")
            
            res = check_usb_signature(serial, name, "1234", "5678", username)
            print(f"[Sim] Server status: Access status is {res.get('status', 'pending').upper()}")
            
            # Take screenshot and webcam grabs
            scr_file = "screenshot_temp.jpg"
            cam_file = "webcam_temp.jpg"
            
            print("[Sim] Device is BLACKLISTED. Triggering visual captures containment (Screen & Webcam)...")
            capture_screenshot(scr_file)
            capture_webcam(cam_file)
            
            log_id = report_threat_event(
                username=username,
                serial=serial,
                action="USB_BLOCKED",
                details=f"Critical Alert: Banned USB Rubber Ducky intrusion attempt blocked on mapped endpoint. Quarantining.",
                severity="critical",
                risk_score=90
            )
            print(f"[Sim] Critical alert registered (Log ID: {log_id}). Uploading visual evidence...")
            
            uploaded = upload_capture_files(log_id, serial, username, screenshot_path=scr_file, webcam_path=cam_file)
            print(f"[Sim] Screenshot and webcam uploads: {uploaded}")
            
            # Clean files
            for f in [scr_file, cam_file]:
                if os.path.exists(f): os.remove(f)
                
        elif choice == '4':
            print("\n[Sim] Simulating drive disconnection...")
            log_id = report_threat_event(
                username=username,
                serial="SIM-RAW-DRIVE",
                action="USB_REMOVE",
                details="Audit Log: Simulated USB device disconnected from drive port.",
                severity="info",
                risk_score=0
            )
            print(f"[Sim] Removal event logged. Log ID: {log_id}")
            
        elif choice == '5':
            print("\nShutting down simulator.")
            break
        else:
            print("Invalid selection. Choose 1-5.")

if __name__ == '__main__':
    print("=======================================================")
    print("         USB GUARDIAN PRO – SECURE AGENT NODE          ")
    print("=======================================================\n")
    
    # 1. Ask for Employee handle to map events
    user_handle = input("Enter Employee username to authenticate session: ").strip()
    if not user_handle:
        user_handle = "employee"
        
    print(f"Session authenticated for employee: '{user_handle}'")
    
    # Start background poller thread to lock/unlock ports via Windows Registry
    start_lockdown_poller(user_handle)
    
    # 2. Select execution mode
    print("\nSelect execution node mode:")
    print("  1. Interactive Threat Simulator (Recommended for testing/demos)")
    print("  2. Hardware USB listener loop (Windows Removable Drive WMI polling)")
    
    mode = input("Select mode (1 or 2): ").strip()
    
    if mode == '2':
        if sys.platform != 'win32':
            print("⚠️ Hardware listener loop is optimized for Windows platforms.")
            confirm = input("Run fallback listener anyway? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Defaulting to interactive simulator mode...")
                run_interactive_simulator(user_handle)
                sys.exit(0)
        run_hardware_listener(user_handle)
    else:
        run_interactive_simulator(user_handle)
