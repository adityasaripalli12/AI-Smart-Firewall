import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from config import Config

def get_db_connection():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Employees table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'employee',
        department TEXT,
        risk_score INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 2. USB Devices table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS usb_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT UNIQUE NOT NULL,
        device_name TEXT,
        vendor_id TEXT,
        product_id TEXT,
        status TEXT NOT NULL DEFAULT 'pending', -- 'allowed', 'blocked', 'pending'
        owner_id INTEGER,
        last_seen TIMESTAMP,
        risk_score INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES employees (id)
    )
    ''')
    
    # 3. Approvals (Pending Reviews) table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        employee_id INTEGER NOT NULL,
        request_reason TEXT,
        status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
        reviewed_by INTEGER,
        comments TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES usb_devices (id),
        FOREIGN KEY (employee_id) REFERENCES employees (id),
        FOREIGN KEY (reviewed_by) REFERENCES employees (id)
    )
    ''')
    
    # 4. Audit Logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        severity TEXT NOT NULL DEFAULT 'info', -- 'info', 'warning', 'critical'
        screenshot_path TEXT,
        webcam_path TEXT,
        usb_serial TEXT,
        risk_score INTEGER DEFAULT 0,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (employee_id) REFERENCES employees (id)
    )
    ''')
    
    # 5. Reports table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_name TEXT NOT NULL,
        report_type TEXT NOT NULL, -- 'PDF', 'CSV', 'Excel'
        file_path TEXT NOT NULL,
        generated_by INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (generated_by) REFERENCES employees (id)
    )
    ''')
    
    # 6. Notifications table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id INTEGER,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0, -- 0 for false, 1 for true
        type TEXT NOT NULL DEFAULT 'info', -- 'alert', 'info', 'success', 'warning'
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (employee_id) REFERENCES employees (id)
    )
    ''')
    
    # 7. Whitelist table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT UNIQUE NOT NULL,
        vendor_id TEXT,
        product_id TEXT,
        device_name TEXT,
        authorized_for INTEGER, -- specific employee, NULL if enterprise-wide
        added_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (authorized_for) REFERENCES employees (id),
        FOREIGN KEY (added_by) REFERENCES employees (id)
    )
    ''')
    
    # 8. Blacklist table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT UNIQUE NOT NULL,
        vendor_id TEXT,
        product_id TEXT,
        device_name TEXT,
        reason TEXT,
        added_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (added_by) REFERENCES employees (id)
    )
    ''')
    
    # 9. Settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')
    
    # --- SEED INITIAL DATA ---
    
    # Seed default settings
    default_settings = {
        'lockdown_mode': 'false',
        'system_access_code': '123456',
        'sensitive_keywords': ','.join(Config.SENSITIVE_KEYWORDS),
        'telegram_bot_token': '',
        'telegram_chat_id': '',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': '587',
        'smtp_user': '',
        'smtp_pass': '',
        'notification_email': '',
        'desktop_alerts': 'true'
    }
    
    for key, val in default_settings.items():
        cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, val))
        
    # Seed Admin employee
    cursor.execute('SELECT * FROM employees WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        admin_pass = generate_password_hash('admin123')
        cursor.execute('''
        INSERT INTO employees (username, email, password_hash, role, department, status)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@usbguardian.com', admin_pass, 'admin', 'Cybersecurity Ops', 'active'))
        
    # Seed Test Employee
    cursor.execute('SELECT * FROM employees WHERE username = ?', ('employee',))
    if not cursor.fetchone():
        emp_pass = generate_password_hash('employee123')
        cursor.execute('''
        INSERT INTO employees (username, email, password_hash, role, department, status, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('employee', 'john.doe@usbguardian.com', emp_pass, 'employee', 'Research & Dev', 'active', 15))
        
    # Get IDs
    cursor.execute('SELECT id FROM employees WHERE username = ?', ('admin',))
    admin_id = cursor.fetchone()[0]
    cursor.execute('SELECT id FROM employees WHERE username = ?', ('employee',))
    emp_id = cursor.fetchone()[0]
    
    # Seed some whitelist items
    whitelist_items = [
        ('USBG-SEC-8891', '0781', '5581', 'SanDisk Cruzer Glide', None, admin_id),
        ('USBG-SEC-2342', '0951', '1666', 'Kingston DataTraveler', emp_id, admin_id)
    ]
    for serial, vid, pid, name, auth_for, added in whitelist_items:
        cursor.execute('''
        INSERT OR IGNORE INTO whitelist (serial_number, vendor_id, product_id, device_name, authorized_for, added_by)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (serial, vid, pid, name, auth_for, added))
        
    # Seed some blacklist items
    blacklist_items = [
        ('BADUSB-666', '1234', '5678', 'Rubber Ducky Payload', 'Malware Injector', admin_id),
        ('STOLEN-VAL-01', 'abcd', '1111', 'Generic External Drive', 'Reported Lost by Employee', admin_id)
    ]
    for serial, vid, pid, name, reason, added in blacklist_items:
        cursor.execute('''
        INSERT OR IGNORE INTO blacklist (serial_number, vendor_id, product_id, device_name, reason, added_by)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (serial, vid, pid, name, reason, added))
        
    # Seed some USB devices
    devices = [
        ('USBG-SEC-8891', 'SanDisk Cruzer Glide', '0781', '5581', 'allowed', admin_id, (datetime.now() - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'), 0),
        ('USBG-SEC-2342', 'Kingston DataTraveler', '0951', '1666', 'allowed', emp_id, (datetime.now() - timedelta(minutes=45)).strftime('%Y-%m-%d %H:%M:%S'), 10),
        ('BADUSB-666', 'Rubber Ducky Payload', '1234', '5678', 'blocked', emp_id, (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'), 90),
        ('UNREG-DRIVE-99', 'Unknown USB Flash', '0aa5', '3c21', 'pending', emp_id, (datetime.now() - timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S'), 45)
    ]
    for serial, name, vid, pid, status, owner, last_seen, risk in devices:
        cursor.execute('''
        INSERT OR IGNORE INTO usb_devices (serial_number, device_name, vendor_id, product_id, status, owner_id, last_seen, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (serial, name, vid, pid, status, owner, last_seen, risk))
        
    # Seed approvals request
    cursor.execute('SELECT id FROM usb_devices WHERE serial_number = ?', ('UNREG-DRIVE-99',))
    device_id = cursor.fetchone()[0]
    cursor.execute('SELECT * FROM approvals WHERE device_id = ?', (device_id,))
    if not cursor.fetchone():
        cursor.execute('''
        INSERT INTO approvals (device_id, employee_id, request_reason, status)
        VALUES (?, ?, ?, ?)
        ''', (device_id, emp_id, 'Need to transfer presentation slides for product release.', 'pending'))
        
    # Seed Audit Logs
    audit_items = [
        (admin_id, 'USER_LOGIN', 'Administrator successfully logged in from console.', '127.0.0.1', 'info', None, None, None, 0, (datetime.now() - timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S')),
        (emp_id, 'USB_INSERT', 'Authorized USB Device Kingston DataTraveler (S/N: USBG-SEC-2342) connected.', '192.168.1.55', 'info', None, None, 'USBG-SEC-2342', 10, (datetime.now() - timedelta(minutes=45)).strftime('%Y-%m-%d %H:%M:%S')),
        (emp_id, 'USB_BLOCKED', 'Critical Alert: Blacklisted USB Device Rubber Ducky (S/N: BADUSB-666) insertion blocked. Screen and Webcam captures triggered.', '192.168.1.55', 'critical', 'static/uploads/mock_screenshot.jpg', 'static/uploads/mock_webcam.jpg', 'BADUSB-666', 90, (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')),
        (emp_id, 'FILE_SCAN', 'Warning: USB Device (S/N: UNREG-DRIVE-99) scanned. Found sensitive file "passwords.xlsx".', '192.168.1.55', 'warning', 'static/uploads/mock_screenshot_file.jpg', None, 'UNREG-DRIVE-99', 45, (datetime.now() - timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S'))
    ]
    
    cursor.execute('SELECT * FROM audit_logs')
    if not cursor.fetchone():
        for employee, action, details, ip, severity, scr, web, serial, risk, timestamp in audit_items:
            cursor.execute('''
            INSERT INTO audit_logs (employee_id, action, details, ip_address, severity, screenshot_path, webcam_path, usb_serial, risk_score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (employee, action, details, ip, severity, scr, web, serial, risk, timestamp))
            
    # Seed Notifications
    notifications_list = [
        (admin_id, 'New approval request pending: USB device UNREG-DRIVE-99.', 0, 'warning'),
        (admin_id, 'Threat blocked: Rubber Ducky S/N BADUSB-666 attempted insertion.', 0, 'alert'),
        (emp_id, 'Your USB Device (S/N: USBG-SEC-2342) has been successfully verified.', 1, 'success')
    ]
    cursor.execute('SELECT * FROM notifications')
    if not cursor.fetchone():
        for emp, msg, read, ntype in notifications_list:
            cursor.execute('''
            INSERT INTO notifications (employee_id, message, is_read, type)
            VALUES (?, ?, ?, ?)
            ''', (emp, msg, read, ntype))
            
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Test initialization
    init_db()
    print("Database initialized successfully.")
