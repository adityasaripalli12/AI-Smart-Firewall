from flask import Blueprint, render_template, redirect, url_for, request, session, flash, send_file
from functools import wraps
from datetime import datetime
import os

from database.db import get_db_connection
from backend.auth import login_required, admin_required
from backend.security import calculate_employee_risk, get_ai_recommendations
from backend.reports import generate_pdf_report, generate_csv_report, generate_excel_report
from telegram.telegram_bot import send_telegram_alert

routes_bp = Blueprint('routes', __name__)

@routes_bp.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('routes.admin_dashboard'))
        return redirect(url_for('routes.dashboard'))
    return redirect(url_for('auth.login'))

@routes_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    """
    Employee panel:
    - View their registered devices
    - Submit approval request for a new device
    - See personal risk score & details
    - View recent activities
    """
    if session.get('role') == 'admin':
        return redirect(url_for('routes.admin_dashboard'))
        
    emp_id = session['user_id']
    conn = get_db_connection()
    
    # Handle Whitelist Request Submission
    if request.method == 'POST':
        serial = request.form.get('serial_number').strip()
        device_name = request.form.get('device_name').strip()
        vid = request.form.get('vendor_id').strip()
        pid = request.form.get('product_id').strip()
        reason = request.form.get('reason').strip()
        
        if not serial or not device_name:
            flash('Serial number and Device name are required.', 'danger')
        else:
            # Check if serial exists in blacklist
            blacklisted = conn.execute("SELECT * FROM blacklist WHERE serial_number = ?", (serial,)).fetchone()
            if blacklisted:
                flash(f'Request rejected: This device is blacklisted. Reason: {blacklisted["reason"]}', 'danger')
            else:
                # Add to usb_devices (default pending)
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO usb_devices (serial_number, device_name, vendor_id, product_id, status, owner_id, last_seen)
                        VALUES (?, ?, ?, ?, 'pending', ?, ?)
                        ON CONFLICT(serial_number) DO UPDATE SET 
                            status = 'pending',
                            device_name = ?,
                            vendor_id = ?,
                            product_id = ?,
                            owner_id = ?
                    ''', (serial, device_name, vid, pid, emp_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), device_name, vid, pid, emp_id))
                    
                    device_id = cursor.lastrowid
                    if not device_id:
                        # Fetch existing
                        dev = conn.execute("SELECT id FROM usb_devices WHERE serial_number = ?", (serial,)).fetchone()
                        device_id = dev['id']
                        
                    # Add to approvals queue
                    conn.execute('''
                        INSERT INTO approvals (device_id, employee_id, request_reason, status)
                        VALUES (?, ?, ?, 'pending')
                    ''', (device_id, emp_id, reason))
                    
                    # Add audit log
                    conn.execute('''
                        INSERT INTO audit_logs (employee_id, action, details, ip_address, severity, usb_serial)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (emp_id, 'APPROVAL_REQUEST', f"Request to whitelist USB Device '{device_name}' (S/N: {serial}).", request.remote_addr, 'info', serial))
                    
                    # Add notification for Admin
                    conn.execute('''
                        INSERT INTO notifications (employee_id, message, type)
                        VALUES (NULL, ?, 'warning')
                    ''', (f"Approval requested by {session['username']}: Whitelist USB device {device_name} (S/N: {serial}).",))
                    
                    conn.commit()
                    flash('Request submitted successfully. Waiting for Admin approval.', 'success')
                except Exception as e:
                    flash(f'An error occurred: {e}', 'danger')
                    
    # Fetch employee stats
    emp = conn.execute('SELECT risk_score, status FROM employees WHERE id = ?', (emp_id,)).fetchone()
    devices = conn.execute('SELECT * FROM usb_devices WHERE owner_id = ?', (emp_id,)).fetchall()
    logs = conn.execute('''
        SELECT timestamp, action, details, severity 
        FROM audit_logs 
        WHERE employee_id = ? 
        ORDER BY timestamp DESC LIMIT 8
    ''', (emp_id,)).fetchall()
    
    # Unread notifications
    notifications = conn.execute('''
        SELECT * FROM notifications 
        WHERE employee_id = ? OR employee_id IS NULL
        ORDER BY created_at DESC LIMIT 5
    ''', (emp_id,)).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                           employee=emp, 
                           devices=devices, 
                           logs=logs, 
                           notifications=notifications)

@routes_bp.route('/admin')
@admin_required
def admin_dashboard():
    """
    Admin dashboard:
    - Main metrics
    - Real-time threat activity stream
    - Lockdown trigger status
    - AI advisory panel
    """
    conn = get_db_connection()
    
    # 1. Fetch metrics
    total_devices = conn.execute("SELECT COUNT(*) FROM usb_devices").fetchone()[0]
    blocked_devices = conn.execute("SELECT COUNT(*) FROM usb_devices WHERE status = 'blocked'").fetchone()[0]
    pending_devices = conn.execute("SELECT COUNT(*) FROM usb_devices WHERE status = 'pending'").fetchone()[0]
    total_employees = conn.execute("SELECT COUNT(*) FROM employees WHERE role = 'employee'").fetchone()[0]
    avg_risk_row = conn.execute("SELECT AVG(risk_score) FROM employees WHERE role = 'employee'").fetchone()
    avg_risk = round(avg_risk_row[0]) if avg_risk_row[0] is not None else 0
    
    # 2. Fetch recent alerts (warning/critical)
    threat_alerts = conn.execute('''
        SELECT a.id, e.username, a.action, a.details, a.severity, a.screenshot_path, a.webcam_path, a.timestamp 
        FROM audit_logs a
        LEFT JOIN employees e ON a.employee_id = e.id
        WHERE a.severity IN ('critical', 'warning')
        ORDER BY a.timestamp DESC LIMIT 6
    ''').fetchall()
    
    # 3. Lockdown status
    lockdown = conn.execute("SELECT value FROM settings WHERE key = 'lockdown_mode'").fetchone()
    is_lockdown = lockdown and lockdown['value'] == 'true'
    
    # 4. Notifications
    notifications = conn.execute('''
        SELECT * FROM notifications 
        WHERE employee_id IS NULL
        ORDER BY created_at DESC LIMIT 5
    ''').fetchall()
    
    # 5. AI Security recommendations
    conn.close()
    ai_recs = get_ai_recommendations()
    
    return render_template('admin_dashboard.html',
                           total_devices=total_devices,
                           blocked_devices=blocked_devices,
                           pending_devices=pending_devices,
                           total_employees=total_employees,
                           avg_risk=avg_risk,
                           threat_alerts=threat_alerts,
                           is_lockdown=is_lockdown,
                           notifications=notifications,
                           ai_recs=ai_recs)

def set_local_usbstor_state(enabled):
    """
    Modifies the local machine's Windows Registry to enable (3) or disable (4) USB storage.
    """
    import sys
    if sys.platform != 'win32':
        return False, "Non-Windows platform"
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
        value = 3 if enabled else 4
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True, "Registry updated successfully"
    except PermissionError:
        return False, "Access Denied. Please restart your Flask server command prompt as Administrator."
    except Exception as e:
        return False, f"Registry error: {e}"

@routes_bp.route('/lockdown', methods=['POST'])
@admin_required
def toggle_lockdown():
    """
    POST route: Enables or disables the global USB lockdown state.
    """
    action = request.form.get('action') # 'disable_all' or 'enable_all'
    
    conn = get_db_connection()
    
    if action == 'disable_all':
        new_state = 'true'
    elif action == 'enable_all':
        new_state = 'false'
    else:
        # Fallback to toggle if no action parameter passed
        lockdown = conn.execute("SELECT value FROM settings WHERE key = 'lockdown_mode'").fetchone()
        current_state = lockdown and lockdown['value'] == 'true'
        new_state = 'false' if current_state else 'true'
        
    conn.execute("UPDATE settings SET value = ? WHERE key = 'lockdown_mode'", (new_state,))
    
    action_text = "EMERGENCY_LOCKDOWN_ON" if new_state == 'true' else "EMERGENCY_LOCKDOWN_OFF"
    details_text = "Global Emergency USB Lockdown enabled by Administrator. All devices blocked." if new_state == 'true' else "Global Emergency USB Lockdown disabled by Administrator."
    severity = "critical" if new_state == 'true' else "info"
    
    # Log the action
    conn.execute('''
        INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (session['user_id'], action_text, details_text, request.remote_addr, severity))
    
    # Admin notification
    conn.execute('''
        INSERT INTO notifications (employee_id, message, type)
        VALUES (NULL, ?, ?)
    ''', (details_text, 'alert' if new_state == 'true' else 'success'))
    
    conn.commit()
    conn.close()
    
    # Telegram dispatch
    send_telegram_alert(f"🚨 <b>SYSTEM LOCKDOWN CHANGE</b>\n{details_text}")
    
    # Physically apply registry state to the local host machine
    # If new_state is 'true' (lockdown active), we disable ports (enabled=False)
    # If new_state is 'false' (lockdown inactive), we enable ports (enabled=True)
    reg_success, reg_msg = set_local_usbstor_state(new_state == 'false')
    
    if not reg_success:
        flash(f"USB policy updated in database. ⚠️ Physical port control failed: {reg_msg}", 'warning')
    else:
        flash(f"USB Ports successfully {'DISABLED (Registry Ports Locked)' if new_state == 'true' else 'ENABLED (Registry Ports Unlocked)'}.", 'danger' if new_state == 'true' else 'success')
        
    return redirect(url_for('routes.admin_dashboard'))

@routes_bp.route('/employees', methods=['GET', 'POST'])
@admin_required
def employees():
    """
    Admin: View employees, modify employee status and risk scores.
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        action = request.form.get('action')
        emp_id = request.form.get('employee_id')
        
        if action == 'suspend':
            conn.execute("UPDATE employees SET status = 'suspended' WHERE id = ?", (emp_id,))
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (?, 'EMPLOYEE_SUSPEND', 'Employee account suspended by Admin.', ?, 'warning')
            ''', (session['user_id'], request.remote_addr))
            flash('Employee suspended.', 'warning')
        elif action == 'activate':
            conn.execute("UPDATE employees SET status = 'active' WHERE id = ?", (emp_id,))
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (?, 'EMPLOYEE_ACTIVATE', 'Employee account activated by Admin.', ?, 'info')
            ''', (session['user_id'], request.remote_addr))
            flash('Employee account activated.', 'success')
        elif action == 'adjust_risk':
            new_risk = request.form.get('risk_score', type=int)
            conn.execute("UPDATE employees SET risk_score = ? WHERE id = ?", (new_risk, emp_id))
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (?, 'RISK_SCORE_ADJUST', 'Employee risk score manually modified to ' || ?, ?, 'info')
            ''', (session['user_id'], new_risk, request.remote_addr))
            flash('Risk score updated.', 'info')
            
        conn.commit()
        
    employees_list = conn.execute("SELECT * FROM employees WHERE role = 'employee'").fetchall()
    conn.close()
    return render_template('employees.html', employees=employees_list)

@routes_bp.route('/usb_devices', methods=['GET', 'POST'])
@admin_required
def usb_devices():
    """
    Admin: View whitelists/blacklists and list all active system USBs.
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        serial = request.form.get('serial_number').strip()
        
        if form_type == 'blacklist_add':
            device_name = request.form.get('device_name')
            vid = request.form.get('vendor_id')
            pid = request.form.get('product_id')
            reason = request.form.get('reason')
            
            # Remove from whitelist if exists
            conn.execute("DELETE FROM whitelist WHERE serial_number = ?", (serial,))
            # Add to blacklist table
            conn.execute('''
                INSERT OR REPLACE INTO blacklist (serial_number, vendor_id, product_id, device_name, reason, added_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (serial, vid, pid, device_name, reason, session['user_id']))
            # Update usb_devices status
            conn.execute("UPDATE usb_devices SET status = 'blocked' WHERE serial_number = ?", (serial,))
            # Log audit
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity, usb_serial)
                VALUES (?, 'USB_BLACKLIST', 'USB device added to global blacklist.', ?, 'warning', ?)
            ''', (session['user_id'], request.remote_addr, serial))
            
            flash('Device added to global blacklist.', 'warning')
            
        elif form_type == 'whitelist_add':
            device_name = request.form.get('device_name')
            vid = request.form.get('vendor_id')
            pid = request.form.get('product_id')
            auth_for = request.form.get('auth_for', type=int) # employee ID or None
            auth_for = auth_for if auth_for != 0 else None
            
            # Remove from blacklist if exists
            conn.execute("DELETE FROM blacklist WHERE serial_number = ?", (serial,))
            # Add to whitelist table
            conn.execute('''
                INSERT OR REPLACE INTO whitelist (serial_number, vendor_id, product_id, device_name, authorized_for, added_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (serial, vid, pid, device_name, auth_for, session['user_id']))
            # Update usb_devices status
            conn.execute("UPDATE usb_devices SET status = 'allowed' WHERE serial_number = ?", (serial,))
            # Log audit
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity, usb_serial)
                VALUES (?, 'USB_WHITELIST', 'USB device added to whitelist.', ?, 'info', ?)
            ''', (session['user_id'], request.remote_addr, serial))
            
            flash('Device added to Whitelist.', 'success')
            
        elif form_type == 'device_delete':
            # Remove device from active tracking
            conn.execute("DELETE FROM usb_devices WHERE serial_number = ?", (serial,))
            conn.execute("DELETE FROM approvals WHERE device_id = (SELECT id FROM usb_devices WHERE serial_number = ?)", (serial,))
            flash('Device removed from inventory.', 'info')
            
        elif form_type == 'device_block':
            # Block a device directly from inventory
            conn.execute("UPDATE usb_devices SET status = 'blocked' WHERE serial_number = ?", (serial,))
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity, usb_serial)
                VALUES (?, 'USB_BLOCK', 'USB Device connection status set to Blocked manually.', ?, 'warning', ?)
            ''', (session['user_id'], request.remote_addr, serial))
            flash('Device blocked.', 'danger')
            
        conn.commit()
        
    devices = conn.execute('''
        SELECT u.*, e.username as owner_name 
        FROM usb_devices u
        LEFT JOIN employees e ON u.owner_id = e.id
    ''').fetchall()
    
    whitelist_items = conn.execute('''
        SELECT w.*, e.username as auth_username 
        FROM whitelist w
        LEFT JOIN employees e ON w.authorized_for = e.id
    ''').fetchall()
    
    blacklist_items = conn.execute("SELECT * FROM blacklist").fetchall()
    employees_list = conn.execute("SELECT id, username FROM employees WHERE role = 'employee'").fetchall()
    
    conn.close()
    
    return render_template('usb_devices.html', 
                           devices=devices, 
                           whitelist=whitelist_items, 
                           blacklist=blacklist_items, 
                           employees=employees_list)

@routes_bp.route('/pending_reviews', methods=['GET', 'POST'])
@admin_required
def pending_reviews():
    """
    Admin: Review and approve/reject pending whitelist requests.
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        approval_id = request.form.get('approval_id')
        action = request.form.get('action') # 'approve' or 'reject'
        comments = request.form.get('comments', '')
        
        # Fetch the approval request
        approval = conn.execute('SELECT * FROM approvals WHERE id = ?', (approval_id,)).fetchone()
        
        if approval:
            # Fetch device details
            device = conn.execute('SELECT * FROM usb_devices WHERE id = ?', (approval['device_id'],)).fetchone()
            
            if device:
                cursor = conn.cursor()
                status_text = 'allowed' if action == 'approve' else 'blocked'
                approval_status = 'approved' if action == 'approve' else 'rejected'
                
                # Update approval request
                cursor.execute('''
                    UPDATE approvals 
                    SET status = ?, reviewed_by = ?, comments = ?, reviewed_at = ? 
                    WHERE id = ?
                ''', (approval_status, session['user_id'], comments, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), approval_id))
                
                # Update device status
                cursor.execute('UPDATE usb_devices SET status = ? WHERE id = ?', (status_text, approval['device_id']))
                
                # If approved, insert into whitelist table
                if action == 'approve':
                    cursor.execute('''
                        INSERT OR REPLACE INTO whitelist (serial_number, vendor_id, product_id, device_name, authorized_for, added_by)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (device['serial_number'], device['vendor_id'], device['product_id'], device['device_name'], approval['employee_id'], session['user_id']))
                    
                # Add log entry
                action_type = 'APPROVAL_APPROVE' if action == 'approve' else 'APPROVAL_REJECT'
                log_details = f"Request for {device['device_name']} (S/N: {device['serial_number']}) {approval_status} by Admin. Comments: {comments}"
                severity = 'info' if action == 'approve' else 'warning'
                
                cursor.execute('''
                    INSERT INTO audit_logs (employee_id, action, details, ip_address, severity, usb_serial)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (approval['employee_id'], action_type, log_details, request.remote_addr, severity, device['serial_number']))
                
                # Add notification for Employee
                cursor.execute('''
                    INSERT INTO notifications (employee_id, message, type)
                    VALUES (?, ?, ?)
                ''', (approval['employee_id'], f"Your USB whitelist request for {device['device_name']} was {approval_status}. Comments: {comments}", 'success' if action == 'approve' else 'warning'))
                
                conn.commit()
                
                # Recalculate employee risk score
                calculate_employee_risk(approval['employee_id'])
                
                flash(f"Whitelist request {approval_status}.", 'success' if action == 'approve' else 'warning')
                
    reviews = conn.execute('''
        SELECT a.id as approval_id, a.request_reason, a.status as approval_status, a.created_at, 
               e.username as emp_name, u.device_name, u.serial_number, u.vendor_id, u.product_id
        FROM approvals a
        JOIN employees e ON a.employee_id = e.id
        JOIN usb_devices u ON a.device_id = u.id
        WHERE a.status = 'pending'
        ORDER BY a.created_at DESC
    ''').fetchall()
    
    conn.close()
    return render_template('pending_reviews.html', reviews=reviews)

@routes_bp.route('/audit_logs')
@admin_required
def audit_logs():
    """
    Admin: Interactive security audit logs filterable by severity and username.
    """
    conn = get_db_connection()
    
    # Filter inputs
    severity_filter = request.args.get('severity', '')
    search_filter = request.args.get('search', '')
    
    query = '''
        SELECT a.*, e.username 
        FROM audit_logs a
        LEFT JOIN employees e ON a.employee_id = e.id
    '''
    params = []
    conditions = []
    
    if severity_filter:
        conditions.append('a.severity = ?')
        params.append(severity_filter)
        
    if search_filter:
        conditions.append('(a.action LIKE ? OR a.details LIKE ? OR e.username LIKE ? OR a.usb_serial LIKE ?)')
        search_term = f"%{search_filter}%"
        params.extend([search_term, search_term, search_term, search_term])
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY a.timestamp DESC"
    
    logs = conn.execute(query, params).fetchall()
    conn.close()
    return render_template('audit_logs.html', logs=logs, severity_filter=severity_filter, search_filter=search_filter)

@routes_bp.route('/analytics')
@admin_required
def analytics():
    """
    Admin: System health, threat analysis charts page.
    """
    # Fetch stats grouping from DB
    conn = get_db_connection()
    
    # 1. Weekly activity logs count (last 7 days)
    weekly_logs = conn.execute('''
        SELECT strftime('%m-%d', timestamp) as day, COUNT(*) as cnt 
        FROM audit_logs 
        WHERE timestamp >= date('now', '-7 days')
        GROUP BY day
        ORDER BY day ASC
    ''').fetchall()
    
    # 2. Risk distribution
    employees_risk = conn.execute('''
        SELECT username, risk_score 
        FROM employees 
        WHERE role = 'employee' 
        ORDER BY risk_score DESC LIMIT 6
    ''').fetchall()
    
    # 3. Action type distribution (threat breakdown)
    threat_distribution = conn.execute('''
        SELECT action, COUNT(*) as cnt 
        FROM audit_logs 
        WHERE severity IN ('critical', 'warning')
        GROUP BY action
    ''').fetchall()
    
    conn.close()
    
    weekly_days = [row['day'] for row in weekly_logs]
    weekly_counts = [row['cnt'] for row in weekly_logs]
    
    risk_names = [row['username'] for row in employees_risk]
    risk_scores = [row['risk_score'] for row in employees_risk]
    
    threat_labels = [row['action'] for row in threat_distribution]
    threat_counts = [row['cnt'] for row in threat_distribution]
    
    return render_template('analytics.html',
                           weekly_days=weekly_days,
                           weekly_counts=weekly_counts,
                           risk_names=risk_names,
                           risk_scores=risk_scores,
                           threat_labels=threat_labels,
                           threat_counts=threat_counts)

@routes_bp.route('/reports')
@admin_required
def reports():
    """
    Admin: Generate and download report summaries.
    """
    conn = get_db_connection()
    reports_history = conn.execute('''
        SELECT r.*, e.username 
        FROM reports r
        JOIN employees e ON r.generated_by = e.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('reports.html', reports=reports_history)

@routes_bp.route('/reports/generate', methods=['POST'])
@admin_required
def trigger_report_generation():
    """
    Triggers generation of reports based on requested formats.
    """
    report_type = request.form.get('report_type') # 'PDF', 'CSV', 'Excel'
    
    try:
        if report_type == 'PDF':
            filename, filepath = generate_pdf_report()
        elif report_type == 'CSV':
            filename, filepath = generate_csv_report()
        elif report_type == 'Excel':
            filename, filepath = generate_excel_report()
        else:
            flash('Invalid report format selected.', 'danger')
            return redirect(url_for('routes.reports'))
            
        # Log to DB
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO reports (report_name, report_type, file_path, generated_by)
            VALUES (?, ?, ?, ?)
        ''', (filename, report_type, filepath, session['user_id']))
        
        # Log audit
        conn.execute('''
            INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
            VALUES (?, 'REPORT_GENERATE', 'Generated cybersecurity summary in ' || ? || ' format.', ?, 'info')
        ''', (session['user_id'], report_type, request.remote_addr))
        
        conn.commit()
        conn.close()
        
        flash(f"{report_type} Report generated successfully.", 'success')
    except Exception as e:
        flash(f"Failed to generate report: {e}", 'danger')
        
    return redirect(url_for('routes.reports'))

@routes_bp.route('/reports/download/<int:report_id>')
@admin_required
def download_report(report_id):
    """
    Sends report file to user.
    """
    conn = get_db_connection()
    report = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()
    
    if report and os.path.exists(report['file_path']):
        return send_file(report['file_path'], as_attachment=True)
        
    flash('File not found or has been deleted.', 'danger')
    return redirect(url_for('routes.reports'))

@routes_bp.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    """
    Admin: Security configurations portal.
    """
    conn = get_db_connection()
    
    if request.method == 'POST':
        # Collect form parameters
        system_access_code = request.form.get('system_access_code', '').strip()
        if not system_access_code:
            system_access_code = '123456'
            
        sensitive_keywords = request.form.get('sensitive_keywords', '').strip()
        telegram_token = request.form.get('telegram_token', '').strip()
        telegram_chat = request.form.get('telegram_chat', '').strip()
        smtp_server = request.form.get('smtp_server', '').strip()
        smtp_port = request.form.get('smtp_port', '').strip()
        smtp_user = request.form.get('smtp_user', '').strip()
        smtp_pass = request.form.get('smtp_pass', '').strip()
        notification_email = request.form.get('notification_email', '').strip()
        desktop_alerts = request.form.get('desktop_alerts') # 'true' or 'false'
        
        # Update settings
        cursor = conn.cursor()
        settings_dict = {
            'system_access_code': system_access_code,
            'sensitive_keywords': sensitive_keywords,
            'telegram_bot_token': telegram_token,
            'telegram_chat_id': telegram_chat,
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'smtp_user': smtp_user,
            'smtp_pass': smtp_pass,
            'notification_email': notification_email,
            'desktop_alerts': 'true' if desktop_alerts else 'false'
        }
        
        for k, v in settings_dict.items():
            cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (k, v))
            
        # Log settings audit change
        conn.execute('''
            INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
            VALUES (?, 'SETTINGS_UPDATE', 'System cybersecurity rules & configurations updated.', ?, 'info')
        ''', (session['user_id'], request.remote_addr))
        
        conn.commit()
        flash('Settings updated successfully.', 'success')
        
    # Read current settings
    settings_rows = conn.execute("SELECT * FROM settings").fetchall()
    conn.close()
    
    current_settings = {row['key']: row['value'] for row in settings_rows}
    return render_template('settings.html', settings=current_settings)
