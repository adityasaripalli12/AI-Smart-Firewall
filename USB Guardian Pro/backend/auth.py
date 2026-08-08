from flask import Blueprint, render_template, redirect, url_for, request, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from database.db import get_db_connection

auth_bp = Blueprint('auth', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if session.get('role') != 'admin':
            flash('Access Denied: Administrative privileges required.', 'danger')
            # Log this unauthorized access attempt
            conn = get_db_connection()
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (session.get('user_id'), 'UNAUTHORIZED_ACCESS', 'User attempted to access admin page.', request.remote_addr, 'warning'))
            conn.commit()
            conn.close()
            return redirect(url_for('routes.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('routes.admin_dashboard'))
        return redirect(url_for('routes.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM employees WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            if user['status'] == 'suspended':
                flash('Your account has been suspended. Please contact security admin.', 'danger')
                conn.execute('''
                    INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user['id'], 'FAILED_LOGIN', 'Suspended user account attempted login.', request.remote_addr, 'warning'))
                conn.commit()
                conn.close()
                return render_template('login.html')
                
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['department'] = user['department']
            
            # Log successful login
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (user['id'], 'USER_LOGIN', 'User logged in successfully.', request.remote_addr, 'info'))
            conn.commit()
            conn.close()
            
            flash(f"Welcome back, {user['username']}!", 'success')
            if user['role'] == 'admin':
                return redirect(url_for('routes.admin_dashboard'))
            return redirect(url_for('routes.dashboard'))
        else:
            # Audit log for failed login attempt
            conn.execute('''
                INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
                VALUES (NULL, ?, ?, ?, ?)
            ''', ('FAILED_LOGIN', f"Failed login attempt for username: {username}", request.remote_addr, 'warning'))
            conn.commit()
            conn.close()
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        department = request.form.get('department')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
            
        conn = get_db_connection()
        # Check if username or email already exists
        user_check = conn.execute('SELECT * FROM employees WHERE username = ? OR email = ?', (username, email)).fetchone()
        if user_check:
            flash('Username or email already registered.', 'danger')
            conn.close()
            return render_template('register.html')
            
        # Create user
        hashed_pass = generate_password_hash(password)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO employees (username, email, password_hash, role, department, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, email, hashed_pass, 'employee', department, 'active'))
        
        user_id = cursor.lastrowid
        
        # Log successful registration
        conn.execute('''
            INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, 'USER_REGISTER', 'New employee registration completed.', request.remote_addr, 'info'))
        
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('register.html')

@auth_bp.route('/logout')
def logout():
    if 'user_id' in session:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO audit_logs (employee_id, action, details, ip_address, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], 'USER_LOGOUT', 'User logged out.', request.remote_addr, 'info'))
        conn.commit()
        conn.close()
        
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
