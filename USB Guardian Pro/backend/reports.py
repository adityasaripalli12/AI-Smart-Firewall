import os
import csv
import openpyxl
from datetime import datetime
from database.db import get_db_connection
from config import Config

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_csv_report():
    """
    Query all audit logs and export them to CSV using python's built-in csv writer.
    """
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT a.id, e.username, a.action, a.details, a.ip_address, a.severity, a.usb_serial, a.risk_score, a.timestamp 
        FROM audit_logs a
        LEFT JOIN employees e ON a.employee_id = e.id
        ORDER BY a.timestamp DESC
    ''').fetchall()
    conn.close()
    
    filename = f"usb_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(Config.BASE_DIR, 'reports', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Log ID', 'Employee', 'Action', 'Details', 'IP Address', 'Severity', 'USB Serial', 'Risk Score', 'Timestamp'])
        for log in logs:
            writer.writerow([
                log['id'],
                log['username'] or 'SYSTEM',
                log['action'],
                log['details'],
                log['ip_address'],
                log['severity'],
                log['usb_serial'] or '',
                log['risk_score'],
                log['timestamp']
            ])
            
    return filename, filepath

def generate_excel_report():
    """
    Query audit logs and usb devices, and export them to Excel sheets using openpyxl directly.
    """
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT a.id, e.username as employee, a.action, a.details, a.ip_address, a.severity, a.usb_serial, a.risk_score, a.timestamp 
        FROM audit_logs a
        LEFT JOIN employees e ON a.employee_id = e.id
        ORDER BY a.timestamp DESC
    ''').fetchall()
    
    devices = conn.execute('''
        SELECT u.id, u.serial_number, u.device_name, u.vendor_id, u.product_id, u.status, e.username as owner, u.last_seen, u.risk_score
        FROM usb_devices u
        LEFT JOIN employees e ON u.owner_id = e.id
    ''').fetchall()
    conn.close()
    
    filename = f"usb_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    filepath = os.path.join(Config.BASE_DIR, 'reports', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    wb = openpyxl.Workbook()
    
    # Sheet 1: Audit Logs
    ws_logs = wb.active
    ws_logs.title = 'Audit Logs'
    ws_logs.append(['Log ID', 'Employee', 'Action', 'Details', 'IP Address', 'Severity', 'USB Serial', 'Risk Score', 'Timestamp'])
    for log in logs:
        ws_logs.append([
            log['id'],
            log['employee'] or 'SYSTEM',
            log['action'],
            log['details'],
            log['ip_address'],
            log['severity'],
            log['usb_serial'] or '',
            log['risk_score'],
            log['timestamp']
        ])
        
    # Sheet 2: USB Inventory
    ws_devs = wb.create_sheet(title='USB Inventory')
    ws_devs.append(['Device ID', 'Serial Number', 'Device Name', 'Vendor ID', 'Product ID', 'Status', 'Owner', 'Last Seen', 'Risk Score'])
    for dev in devices:
        ws_devs.append([
            dev['id'],
            dev['serial_number'],
            dev['device_name'],
            dev['vendor_id'] or '',
            dev['product_id'] or '',
            dev['status'],
            dev['owner'] or 'SYSTEM',
            dev['last_seen'] or '',
            dev['risk_score']
        ])
        
    wb.save(filepath)
    return filename, filepath

def generate_pdf_report():
    """
    Generates a beautifully designed PDF Security Audit Report using ReportLab.
    """
    conn = get_db_connection()
    
    # Get stats
    total_devices = conn.execute("SELECT COUNT(*) FROM usb_devices").fetchone()[0]
    blocked_devices = conn.execute("SELECT COUNT(*) FROM usb_devices WHERE status = 'blocked'").fetchone()[0]
    pending_devices = conn.execute("SELECT COUNT(*) FROM usb_devices WHERE status = 'pending'").fetchone()[0]
    critical_logs = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE severity = 'critical'").fetchone()[0]
    
    # Get logs
    logs = conn.execute('''
        SELECT a.timestamp, e.username, a.action, a.severity, a.details 
        FROM audit_logs a
        LEFT JOIN employees e ON a.employee_id = e.id
        ORDER BY a.timestamp DESC LIMIT 15
    ''').fetchall()
    
    conn.close()
    
    filename = f"usb_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(Config.BASE_DIR, 'reports', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#00ff88'), # Neon green highlight
        spaceAfter=15,
        alignment=1 # Center
    )
    
    subtitle_style = ParagraphStyle(
        'SubtitleStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        textColor=colors.HexColor('#ffffff'),
        spaceAfter=25,
        alignment=1
    )
    
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#00d2ff'), # Blue highlight
        spaceBefore=15,
        spaceAfter=10
    )
    
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#b3c5d6'),
        spaceAfter=8
    )
    
    # Render PDF Background & Content (Professional Dark Theme layout)
    story.append(Paragraph("USB GUARDIAN PRO", title_style))
    story.append(Paragraph("ENTERPRISE CYBERSECURITY DASHBOARD - SECURITY AUDIT REPORT", subtitle_style))
    story.append(Spacer(1, 10))
    
    # Metadata Table
    meta_data = [
        [Paragraph("<b>Generated On:</b>", body_style), Paragraph(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), body_style)],
        [Paragraph("<b>Report Type:</b>", body_style), Paragraph("Enterprise Security Audit Log", body_style)],
        [Paragraph("<b>Status:</b>", body_style), Paragraph("COMPLETED (SOC-AUTO)", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[120, 300])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#0d1821')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1f3347')),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 20))
    
    # Executive Summary Metrics
    story.append(Paragraph("Executive Summary Metrics", h2_style))
    metrics_data = [
        [Paragraph("<b>Metric Name</b>", body_style), Paragraph("<b>Value</b>", body_style), Paragraph("<b>Alert Status</b>", body_style)],
        [Paragraph("Total Monitored USB Devices", body_style), Paragraph(str(total_devices), body_style), Paragraph("Operational", body_style)],
        [Paragraph("Active Blocked USB Threats", body_style), Paragraph(str(blocked_devices), body_style), Paragraph("HIGH RISK" if blocked_devices > 0 else "Normal", body_style)],
        [Paragraph("Pending Device Approvals", body_style), Paragraph(str(pending_devices), body_style), Paragraph("Action Required" if pending_devices > 0 else "Normal", body_style)],
        [Paragraph("Critical Security Incidents", body_style), Paragraph(str(critical_logs), body_style), Paragraph("IMMEDIATE QUARANTINE" if critical_logs > 0 else "Normal", body_style)]
    ]
    t_metrics = Table(metrics_data, colWidths=[200, 100, 150])
    t_metrics.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1f3347')),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#0d1821')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1f3347')),
    ]))
    story.append(t_metrics)
    story.append(Spacer(1, 25))
    
    # Incident Audit Logs
    story.append(Paragraph("Recent Cybersecurity Audit Log (Max 15)", h2_style))
    log_data = [[
        Paragraph("<b>Timestamp</b>", body_style), 
        Paragraph("<b>Employee</b>", body_style), 
        Paragraph("<b>Action</b>", body_style), 
        Paragraph("<b>Severity</b>", body_style), 
        Paragraph("<b>Details</b>", body_style)
    ]]
    for log in logs:
        # Wrap in paragraphs for auto text wrapping
        log_data.append([
            Paragraph(log['timestamp'], body_style),
            Paragraph(log['username'] or 'SYSTEM', body_style),
            Paragraph(log['action'], body_style),
            Paragraph(log['severity'].upper(), body_style),
            Paragraph(log['details'], body_style)
        ])
    t_logs = Table(log_data, colWidths=[100, 60, 90, 60, 200])
    t_logs.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1f3347')),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#0d1821')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1f3347')),
    ]))
    story.append(t_logs)
    
    # Build Document
    doc.build(story)
    
    return filename, filepath
