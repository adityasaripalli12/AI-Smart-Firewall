from flask import Blueprint, request, jsonify, current_app
import os
import uuid
from datetime import datetime
from database.db import get_db_connection
from backend.security import calculate_employee_risk
from telegram.telegram_bot import send_telegram_alert
from config import Config

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/check_status', methods=['POST'])
def check_status():
    """
    Called by the agent when a USB is connected or polled.
    Checks if system is locked down, or if the device is whitelisted/blacklisted.
    """
    data = request.json or {}
    serial = data.get('serial_number')
    device_name = data.get('device_name', 'Unknown USB')
    vid = data.get('vendor_id', '')
    pid = data.get('product_id', '')
    username = data.get('username')
    
    if not serial:
        return jsonify({'status': 'error', 'message': 'Missing serial_number'}), 400
        
    conn = get_db_connection()
    try:
        # 1. Check Global Lockdown
        lockdown = conn.execute("SELECT value FROM settings WHERE key = 'lockdown_mode'").fetchone()
        is_lockdown = lockdown and lockdown['value'] == 'true'
        
        if is_lockdown:
            return jsonify({
                'status': 'blocked',
                'reason': 'System is in global Emergency Lockdown. All USB devices are disabled.'
            })
            
        # Get employee ID
        employee = None
        if username:
            employee = conn.execute("SELECT id FROM employees WHERE username = ?", (username,)).fetchone()
            
        emp_id = employee['id'] if employee else None
            
        # 2. Check Blacklist
        blacklisted = conn.execute("SELECT * FROM blacklist WHERE serial_number = ?", (serial,)).fetchone()
        if blacklisted:
            return jsonify({
                'status': 'blocked',
                'reason': f"Device is blacklisted: {blacklisted['reason']}"
            })
            
        # 3. Check Whitelist
        whitelisted = conn.execute('''
            SELECT * FROM whitelist 
            WHERE serial_number = ? AND (authorized_for IS NULL OR authorized_for = ?)
        ''', (serial, emp_id)).fetchone()
        
        if whitelisted:
            # Update device status to allowed in active device log
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO usb_devices (serial_number, device_name, vendor_id, product_id, status, owner_id, last_seen)
                VALUES (?, ?, ?, ?, 'allowed', ?, ?)
                ON CONFLICT(serial_number) DO UPDATE SET 
                    status = 'allowed',
                    last_seen = ?,
                    owner_id = COALESCE(?, owner_id)
            ''', (serial, device_name, vid, pid, emp_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), datetime.now().strftime('%Y-%m-%d %H:%M:%S'), emp_id))
            conn.commit()
            return jsonify({'status': 'allowed'})
            
        # 4. Check existing USB device logs
        device = conn.execute("SELECT status FROM usb_devices WHERE serial_number = ?", (serial,)).fetchone()
        
        if device:
            # Return current status (e.g. 'pending' or 'blocked')
            return jsonify({'status': device['status']})
        else:
            # Register device as pending
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO usb_devices (serial_number, device_name, vendor_id, product_id, status, owner_id, last_seen)
                VALUES (?, ?, ?, ?, 'pending', ?, ?)
            ''', (serial, device_name, vid, pid, emp_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            
            # Notify admins of a new device insertion awaiting review
            conn.execute('''
                INSERT INTO notifications (employee_id, message, type)
                VALUES (NULL, ?, 'warning')
            ''', (f"New unregistered USB device connected by {username or 'Guest'}: {device_name} (S/N: {serial}). Awaiting review.",))
            conn.commit()
            
            return jsonify({
                'status': 'pending',
                'reason': 'Device unregistered. Whitelist approval request submitted automatically.'
            })
    except Exception as e:
        print(f"Error in api/check_status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()

@api_bp.route('/api/report_event', methods=['POST'])
def report_event():
    """
    Called by the agent to log actions (USB_INSERT, USB_REMOVE, FILE_SCAN/SENSITIVE_HIT, LOCKDOWN_BREACH).
    """
    data = request.json or {}
    username = data.get('username')
    serial = data.get('serial_number')
    action = data.get('action') # e.g., 'USB_INSERT', 'USB_REMOVE', 'SENSITIVE_FILE_DETECTED'
    details = data.get('details', '')
    severity = data.get('severity', 'info')
    risk_score = data.get('risk_score', 0)
    
    conn = get_db_connection()
    try:
        # Resolve employee ID
        employee = None
        if username:
            employee = conn.execute("SELECT id FROM employees WHERE username = ?", (username,)).fetchone()
        emp_id = employee['id'] if employee else None
        
        # Log to audit_logs
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (employee_id, action, details, ip_address, severity, usb_serial, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (emp_id, action, details, request.remote_addr, severity, serial, risk_score))
        log_id = cursor.lastrowid
        conn.commit()
        
        # Update employee risk score
        if emp_id:
            calculate_employee_risk(emp_id)
            
        # Push notification
        ntype = 'info'
        if severity == 'critical':
            ntype = 'alert'
        elif severity == 'warning':
            ntype = 'warning'
            
        conn.execute('''
            INSERT INTO notifications (employee_id, message, type)
            VALUES (?, ?, ?)
        ''', (emp_id if emp_id else None, details, ntype))
        conn.commit()
        
        # Telegram notification on critical alerts
        if severity == 'critical':
            send_telegram_alert(f"🔴 <b>CRITICAL EVENT LOGGED</b>\n<b>User:</b> {username or 'SYSTEM'}\n<b>Action:</b> {action}\n<b>Details:</b> {details}\n<b>Risk Score:</b> {risk_score}")
            
        return jsonify({'success': True, 'log_id': log_id})
    except Exception as e:
        print(f"Error in api/report_event: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@api_bp.route('/api/upload_capture', methods=['POST'])
def upload_capture():
    """
    Called by the agent to upload screenshot or webcam photos when security rule violations occur.
    """
    serial = request.form.get('serial_number')
    username = request.form.get('username')
    log_id = request.form.get('log_id')
    
    screenshot = request.files.get('screenshot')
    webcam = request.files.get('webcam')
    
    screenshot_filename = None
    webcam_filename = None
    
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if screenshot:
        screenshot_filename = f"screenshot_{serial}_{timestamp_str}.jpg"
        screenshot_path = os.path.join(Config.UPLOAD_FOLDER, screenshot_filename)
        screenshot.save(screenshot_path)
        
    if webcam:
        webcam_filename = f"webcam_{serial}_{timestamp_str}.jpg"
        webcam_path = os.path.join(Config.UPLOAD_FOLDER, webcam_filename)
        webcam.save(webcam_path)
        
    conn = get_db_connection()
    try:
        # Link uploads to the latest audit log or specific log_id
        if log_id:
            cursor = conn.cursor()
            if screenshot_filename:
                cursor.execute('UPDATE audit_logs SET screenshot_path = ? WHERE id = ?', (f"static/uploads/{screenshot_filename}", log_id))
            if webcam_filename:
                cursor.execute('UPDATE audit_logs SET webcam_path = ? WHERE id = ?', (f"static/uploads/{webcam_filename}", log_id))
            conn.commit()
        else:
            # Find the latest log for this employee/usb
            employee = None
            if username:
                employee = conn.execute("SELECT id FROM employees WHERE username = ?", (username,)).fetchone()
            emp_id = employee['id'] if employee else None
            
            latest_log = conn.execute('''
                SELECT id FROM audit_logs 
                WHERE employee_id = ? AND usb_serial = ? 
                ORDER BY timestamp DESC LIMIT 1
            ''', (emp_id, serial)).fetchone()
            
            if latest_log:
                cursor = conn.cursor()
                if screenshot_filename:
                    cursor.execute('UPDATE audit_logs SET screenshot_path = ? WHERE id = ?', (f"static/uploads/{screenshot_filename}", latest_log['id']))
                if webcam_filename:
                    cursor.execute('UPDATE audit_logs SET webcam_path = ? WHERE id = ?', (f"static/uploads/{webcam_filename}", latest_log['id']))
                conn.commit()
                
        # Send Telegram alert update with the image (screenshot as priority)
        token_row = conn.execute("SELECT value FROM settings WHERE key = 'telegram_bot_token'").fetchone()
        chat_row = conn.execute("SELECT value FROM settings WHERE key = 'telegram_chat_id'").fetchone()
        
        bot_token = token_row['value'] if token_row else ''
        chat_id = chat_row['value'] if chat_row else ''
        
        # If telegram is configured, dispatch the photo
        if bot_token and chat_id:
            active_img = screenshot_filename or webcam_filename
            if active_img:
                img_path = os.path.join(Config.UPLOAD_FOLDER, active_img)
                send_telegram_alert(f"📸 <b>INCIDENT PHOTO CAPTURED</b>\n<b>User:</b> {username}\n<b>USB Serial:</b> {serial}", img_path)
                
        return jsonify({
            'success': True,
            'screenshot_path': f"static/uploads/{screenshot_filename}" if screenshot_filename else None,
            'webcam_path': f"static/uploads/{webcam_filename}" if webcam_filename else None
        })
    except Exception as e:
        print(f"Error uploading captures: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

@api_bp.route('/api/dashboard_stats')
def dashboard_stats():
    """
    JSON statistics feeding dynamic frontend dashboard panels.
    """
    conn = get_db_connection()
    try:
        # Core counts
        total_devices = conn.execute("SELECT COUNT(*) FROM usb_devices").fetchone()[0]
        blocked_devices = conn.execute("SELECT COUNT(*) FROM usb_devices WHERE status = 'blocked'").fetchone()[0]
        pending_devices = conn.execute("SELECT COUNT(*) FROM usb_devices WHERE status = 'pending'").fetchone()[0]
        total_employees = conn.execute("SELECT COUNT(*) FROM employees WHERE role = 'employee'").fetchone()[0]
        
        # Threat logs
        recent_threats = conn.execute('''
            SELECT a.timestamp, e.username, a.details, a.severity 
            FROM audit_logs a
            LEFT JOIN employees e ON a.employee_id = e.id
            WHERE a.severity IN ('critical', 'warning')
            ORDER BY a.timestamp DESC LIMIT 5
        ''').fetchall()
        
        # Settings
        lockdown = conn.execute("SELECT value FROM settings WHERE key = 'lockdown_mode'").fetchone()
        is_lockdown = lockdown and lockdown['value'] == 'true'
        
        threats_list = []
        for r in recent_threats:
            threats_list.append({
                'timestamp': r['timestamp'],
                'username': r['username'] or 'SYSTEM',
                'details': r['details'],
                'severity': r['severity']
            })
            
        return jsonify({
            'stats': {
                'total_devices': total_devices,
                'blocked_devices': blocked_devices,
                'pending_devices': pending_devices,
                'total_employees': total_employees
            },
            'lockdown_active': is_lockdown,
            'recent_threats': threats_list
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@api_bp.route('/api/lockdown_status')
def lockdown_status():
    """
    Returns the current global lockdown state to the client agent.
    """
    conn = get_db_connection()
    try:
        lockdown = conn.execute("SELECT value FROM settings WHERE key = 'lockdown_mode'").fetchone()
        is_lockdown = lockdown and lockdown['value'] == 'true'
        return jsonify({'lockdown_active': is_lockdown})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


# --------------------------------------------------
# Emergency Protocol API Endpoints
# --------------------------------------------------

@api_bp.route('/api/emergency/verify_code', methods=['POST'])
def emergency_verify_code():
    """
    Verifies the Emergency Access Code entered by the admin.
    Compares against the system_access_code stored in the settings table.
    Logs both successful and failed verification attempts.
    """
    from flask import session as flask_session
    if 'user_id' not in flask_session or flask_session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Admin authentication required.'}), 403

    data = request.get_json() or {}
    entered_code = data.get('code', '').strip()

    conn = get_db_connection()
    try:
        # Fetch stored access code from settings
        row = conn.execute("SELECT value FROM settings WHERE key = 'system_access_code'").fetchone()
        stored_code = row['value'] if row else '123456'

        if entered_code == stored_code:
            # Log successful verification
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (?, 'EMERGENCY_CODE_VERIFIED', 'Emergency Protocol access code verified successfully.', ?, 'warning')
            ''', (flask_session['user_id'], request.remote_addr))
            conn.commit()
            return jsonify({'success': True, 'message': 'Access code verified.'})
        else:
            # Log failed attempt
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (?, 'EMERGENCY_CODE_FAILED', 'Emergency Protocol: Incorrect access code entered. Access denied.', ?, 'critical')
            ''', (flask_session['user_id'], request.remote_addr))
            conn.commit()
            return jsonify({'success': False, 'message': 'Access Denied: Incorrect emergency code.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()


@api_bp.route('/api/emergency/usb_action', methods=['POST'])
def emergency_usb_action():
    """
    Executes USB Enable or Disable via Windows Registry (USBSTOR Start value).
    Reuses set_local_usbstor_state from backend.routes — no duplicate logic.
    Records every action in audit_logs with username, action, result, and timestamp.
    """
    from flask import session as flask_session
    from backend.routes import set_local_usbstor_state

    if 'user_id' not in flask_session or flask_session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Admin authentication required.'}), 403

    data = request.get_json() or {}
    action = data.get('action')  # 'enable' or 'disable'

    if action not in ('enable', 'disable'):
        return jsonify({'success': False, 'message': 'Invalid action. Use enable or disable.'}), 400

    enable = (action == 'enable')
    reg_success, reg_msg = set_local_usbstor_state(enable)

    registry_value = 3 if enable else 4
    usb_status = 'ENABLED' if enable else 'DISABLED'
    action_label = 'EMERGENCY_USB_ENABLE' if enable else 'EMERGENCY_USB_DISABLE'
    severity = 'info' if enable else 'critical'
    details = (
        f"Emergency Protocol executed by {flask_session.get('username', 'admin')}: "
        f"USB ports {usb_status}. Registry USBSTOR\\Start set to {registry_value}. "
        f"Registry result: {reg_msg}"
    )

    conn = get_db_connection()
    try:
        # Update lockdown_mode in settings to keep DB in sync
        new_lockdown = 'true' if not enable else 'false'
        conn.execute("UPDATE settings SET value = ? WHERE key = 'lockdown_mode'", (new_lockdown,))

        # Log to audit_logs
        conn.execute('''
            INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (flask_session['user_id'], action_label, details, request.remote_addr, severity))

        # Push notification
        conn.execute('''
            INSERT INTO notifications (employee_id, message, type)
            VALUES (NULL, ?, ?)
        ''', (details, 'alert' if not enable else 'success'))

        conn.commit()

        if reg_success:
            return jsonify({
                'success': True,
                'usb_status': usb_status,
                'registry_value': registry_value,
                'message': f'USB ports successfully {usb_status}. Registry Start = {registry_value}.'
            })
        else:
            return jsonify({
                'success': False,
                'usb_status': usb_status,
                'registry_value': registry_value,
                'message': f'DB updated but registry change failed: {reg_msg}'
            })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()
