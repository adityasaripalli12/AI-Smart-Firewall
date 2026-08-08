from database.db import get_db_connection
from config import Config

def calculate_employee_risk(employee_id):
    """
    Calculate and update an employee's risk score based on their history:
    - Critical logs (USB blocked, lockdown breaches): +40 points each
    - Warning logs (Sensitive file scans, unapproved access): +20 points each
    - Info logs: +2 points each
    - Whitelisted devices: -5 points each (incentivizes compliance)
    - Suspended status: +10 points base
    Clamped between 0 and 100.
    """
    if not employee_id:
        return 0
        
    conn = get_db_connection()
    try:
        # Get count of logs by severity
        logs = conn.execute('''
            SELECT severity, COUNT(*) as cnt 
            FROM audit_logs 
            WHERE employee_id = ? 
            GROUP BY severity
        ''', (employee_id,)).fetchall()
        
        log_counts = {row['severity']: row['cnt'] for row in logs}
        
        info_count = log_counts.get('info', 0)
        warning_count = log_counts.get('warning', 0)
        critical_count = log_counts.get('critical', 0)
        
        # Get count of whitelisted devices
        allowed_count = conn.execute('''
            SELECT COUNT(*) 
            FROM usb_devices 
            WHERE owner_id = ? AND status = 'allowed'
        ''', (employee_id,)).fetchone()[0]
        
        # Calculate score
        score = (critical_count * Config.RISK_UNAUTHORIZED_USB) + \
                (warning_count * Config.RISK_SENSITIVE_FILE_HIT) + \
                (info_count * 2) - \
                (allowed_count * 5)
        
        # Base status adjustment
        emp = conn.execute('SELECT status FROM employees WHERE id = ?', (employee_id,)).fetchone()
        if emp and emp['status'] == 'suspended':
            score += 20
            
        # Clamp score between 0 and 100
        score = max(0, min(100, score))
        
        # Update score in database
        conn.execute('UPDATE employees SET risk_score = ? WHERE id = ?', (score, employee_id))
        conn.commit()
        return score
    except Exception as e:
        print(f"Error calculating employee risk score: {e}")
        return 0
    finally:
        conn.close()

def get_ai_recommendations():
    """
    Generates intelligent cybersecurity advisory notes based on recent audit log data.
    """
    conn = get_db_connection()
    recommendations = []
    
    try:
        # 1. Check for recent critical events
        critical_logs = conn.execute('''
            SELECT a.*, e.username 
            FROM audit_logs a 
            LEFT JOIN employees e ON a.employee_id = e.id 
            WHERE a.severity = 'critical' 
            ORDER BY a.timestamp DESC LIMIT 5
        ''').fetchall()
        
        # 2. Check for recent warning events
        warning_logs = conn.execute('''
            SELECT a.*, e.username 
            FROM audit_logs a 
            LEFT JOIN employees e ON a.employee_id = e.id 
            WHERE a.severity = 'warning' 
            ORDER BY a.timestamp DESC LIMIT 5
        ''').fetchall()
        
        # 3. Check for lockdown status
        lockdown = conn.execute("SELECT value FROM settings WHERE key = 'lockdown_mode'").fetchone()
        is_lockdown = lockdown and lockdown['value'] == 'true'
        
        if is_lockdown:
            recommendations.append({
                'title': 'Emergency Lockdown Active',
                'severity': 'danger',
                'description': 'The system is in full lockdown mode. All USB data transfers are completely disabled. Review all logs for unauthorized connection attempts during this state.',
                'action': 'Disable Lockdown once the threat is isolated.'
            })
            
        if critical_logs:
            for log in critical_logs:
                if 'BADUSB' in str(log['details']).upper() or 'RUBBER' in str(log['details']).upper():
                    recommendations.append({
                        'title': f"Rubber Ducky Payload Detected on {log['username'] or 'Endpoint'}",
                        'severity': 'danger',
                        'description': f"A malicious USB device attempted injection at {log['timestamp']}. Immediate device quarantine is recommended.",
                        'action': f"Review screenshot and webcam logs for {log['username'] or 'incident machine'}."
                    })
                elif 'LOCKDOWN' in str(log['action']):
                    recommendations.append({
                        'title': 'Lockdown Violation Attempt',
                        'severity': 'danger',
                        'description': f"An endpoint attempted to register a USB during global lockdown at {log['timestamp']}.",
                        'action': 'Investigate host endpoint network configuration immediately.'
                    })
                    
        if warning_logs:
            sensitive_hits = [log for log in warning_logs if 'SENSITIVE' in str(log['details']).upper() or 'FILE' in str(log['details']).upper()]
            if sensitive_hits:
                recommendations.append({
                    'title': 'Sensitive Data Leak Danger',
                    'severity': 'warning',
                    'description': f"Recent scans detected confidential keywords (e.g. passwords, SSN, financial) on unencrypted USB drives.",
                    'action': 'Enforce mandatory USB encryption policies and roll out Data Loss Prevention (DLP) training.'
                })
                
        # Fallback / Default advice
        if not recommendations:
            recommendations.append({
                'title': 'All Systems Nominal',
                'severity': 'success',
                'description': 'No critical alerts or policy violations recorded in the past 24 hours. The risk profile of the network is currently low.',
                'action': 'Maintain routine security updates and review whitelisted signatures.'
            })
            
    except Exception as e:
        print(f"Error generating AI recommendations: {e}")
        recommendations.append({
            'title': 'Security Advisory Engine Offline',
            'severity': 'warning',
            'description': 'Could not parse logs to generate security recommendations.',
            'action': 'Verify database connectivity.'
        })
    finally:
        conn.close()
        
    return recommendations
