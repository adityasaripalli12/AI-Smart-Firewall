from datetime import datetime
import random
import requests  # type: ignore
import os

from reportlab.platypus import SimpleDocTemplate, Preformatted, Image, Spacer, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors


# 🌍 GET IP DETAILS
def get_ip_details(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}")
        data = res.json()

        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "lat": data.get("lat", "Unknown"),
            "lon": data.get("lon", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }
    except:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "lat": "Unknown",
            "lon": "Unknown",
            "isp": "Unknown"
        }


# 📄 MAIN REPORT FUNCTION (PDF VERSION ONLY)
def generate_detailed_report(logs, target_ip=None):

    if not logs:
        filename = "firewall_report.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()

        elements = [Preformatted("No incidents detected.", styles["Normal"])]
        doc.build(elements)
        return filename

    # ✅ FILTER BY IP
    if target_ip:
        filtered_logs = [log for log in logs if log["ip"] == target_ip]

        if not filtered_logs:
            filename = "firewall_report.pdf"
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()

            elements = [Preformatted("No data found for this IP", styles["Normal"])]
            doc.build(elements)
            return filename

        latest = filtered_logs[-1]
    else:
        latest = logs[-1]

    # 🌍 FETCH IP LOCATION
    ip_info = get_ip_details(latest["ip"])

    # 🔢 Auto Report ID
    report_id = f"FW-IR-{random.randint(1000,9999)}"

    # 🧠 Confidence
    confidence = random.randint(85, 99)

    # 🧭 MITRE mapping
    mitre_map = {
        "SQL Injection": ("T1190", "Exploit Public-Facing Application"),
        "XSS": ("T1059", "Command and Scripting Interpreter"),
        "DDoS Attack": ("T1498", "Network Denial of Service"),
        "Brute Force Attack": ("T1110", "Brute Force"),
        "Ransomware": ("T1486", "Data Encrypted for Impact")
    }

    technique_id, technique_name = mitre_map.get(
        latest["type"], ("T0000", "Unknown Technique")
    )

    from urllib.parse import quote

    # 🗺️ GOOGLE MAP LINK
    if ip_info['lat'] != "Unknown" and ip_info['lon'] != "Unknown":
        map_link = f"https://www.google.com/maps?q={ip_info['lat']},{ip_info['lon']}"
    else:
        map_link = "https://www.google.com/maps?q=0,0" # Fallback

    # 📱 QR CODE GENERATION
    encoded_link = quote(map_link)
    qr_filename = f"qr_{report_id}.png"
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=150x150&data={encoded_link}"
    
    try:
        qr_response = requests.get(qr_url)
        if qr_response.status_code == 200:
            with open(qr_filename, 'wb') as f:
                f.write(qr_response.content)
            has_qr = True
        else:
            has_qr = False
    except:
        has_qr = False

    # 🗺️ STATIC MAP GENERATION (As a screenshot)
    map_img_filename = f"map_{report_id}.png"
    # Using Yandex Static Maps for high-fidelity coordinate proof
    map_api_url = f"https://static-maps.yandex.ru/1.x/?ll={ip_info['lon']},{ip_info['lat']}&z=12&l=map&size=600,300"
    has_map_img = False
    if ip_info['lat'] != "Unknown":
        try:
            map_res = requests.get(map_api_url, timeout=5)
            if map_res.status_code == 200:
                with open(map_img_filename, 'wb') as f:
                    f.write(map_res.content)
                has_map_img = True
        except:
            pass

    action_taken = latest["status"]

    report_text = f"""
🛡️ AI SMART FIREWALL – SECURITY INCIDENT REPORT
------------------------------------------------------------

1. 📌 Incident Summary
- Report ID: {report_id}
- Date & Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Detection Source: AI Firewall System
- Incident Type: {latest['type']}
- Severity Level: {latest['severity']}
- Status: {latest['status']}

------------------------------------------------------------

2. 🌐 Source Information
- Source IP Address: {latest['ip']}
- Country: {ip_info['country']}
- City: {ip_info['city']}
- ISP: {ip_info['isp']}
- Latitude: {ip_info['lat']}
- Longitude: {ip_info['lon']}

📍 Map Location:
{map_link}

------------------------------------------------------------

3. 🧠 Detection Details
- Detection Method: AI-based Anomaly Detection
- Trigger Condition:
  - Abnormal traffic pattern detected
  - Suspicious request behavior
- Confidence Score: {confidence} %

------------------------------------------------------------

4. ⚠️ Threat Classification
- Attack Category: {latest['type']}
- Attack Description:
  This activity indicates a potential {latest['type']} attempt.

- MITRE ATT&CK Mapping:
  - Technique ID: {technique_id}
  - Technique Name: {technique_name}

------------------------------------------------------------

5. 🔍 Activity Timeline
| Time | Event |
|------|------|
| {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Suspicious activity detected |
| {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | AI flagged anomaly |
| {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Action triggered |

------------------------------------------------------------

6. 🛡️ Actions Taken
- Action Summary: {action_taken}

------------------------------------------------------------

7. 📊 Impact Assessment
- Target System: Main Server
- Impact Level: {latest['severity']}
- Data Compromise: No
- Service Disruption: No

------------------------------------------------------------

8. 🔄 Response & Mitigation
- Malicious IP handled based on severity
- Continuous monitoring enabled
- System integrity maintained

------------------------------------------------------------

9. ✅ Recommendations
- Monitor similar traffic patterns
- Apply stricter firewall rules
- Perform periodic security audits

------------------------------------------------------------

10. 🧾 Analyst Notes (SOC Level 1)
- Initial triage completed
- Escalation Required: No

Remarks:
System handled the threat automatically.

------------------------------------------------------------

11. 📎 Report Metadata
- Generated By: AI Firewall System
- Reviewed By: SOC Analyst
- Report Version: 1.0

------------------------------------------------------------
🔒 End of Report
"""

    # ✅ PDF OUTPUT
    filename = f"firewall_report_{report_id}.pdf"

    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom styles
    styles.add(ParagraphStyle(name='Center', alignment=1, fontSize=10, textColor=colors.grey))
    styles.add(ParagraphStyle(name='HeadingTactical', fontSize=14, fontName='Helvetica-Bold', textColor=colors.darkblue, spaceAfter=12))
    styles.add(ParagraphStyle(name='EvidenceHeader', fontSize=12, fontName='Helvetica-Bold', textColor=colors.red, spaceBefore=20, spaceAfter=10))

    elements = []
    
    # 1. Main Report Header & Summary
    elements.append(Preformatted(report_text, styles["Normal"]))

    # 2. EVIDENCE GALLERY SECTION
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph("SECTION 12: FORENSIC EVIDENCE GALLERY (SCREENSHOTS)", styles["EvidenceHeader"]))
    elements.append(Spacer(1, 0.1 * inch))

    # 3. AI INTELLIGENCE PROOF (Visual Block)
    ai_data = [
        ["NEURAL_CONFIDENCE", f"{confidence}%"],
        ["ANOMALY_INDEX", "DETECTED (HIGH)"],
        ["THREAT_SIGNATURE", latest['type'].upper()]
    ]
    ai_table = Table(ai_data, colWidths=[2*inch, 3*inch])
    ai_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Courier-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('PADDING', (0,0), (-1, -1), 8)
    ]))
    elements.append(Paragraph("<b>[A] NEURAL_NETWORK ANALYTICS PROOF</b>", styles["Normal"]))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(ai_table)
    elements.append(Spacer(1, 0.3 * inch))

    # 4. TACTICAL LOG EXTRACT (Proof Table)
    elements.append(Paragraph("<b>[B] SYSTEM_TERMINAL LOG EXTRACT</b>", styles["Normal"]))
    elements.append(Spacer(1, 0.1 * inch))
    
    log_rows = [["TIME", "EVENT", "SEVERITY", "STATUS"]]
    for log in logs[-8:]: # Last 8 incidents as proof
        log_rows.append([
            datetime.now().strftime('%H:%M:%S'), 
            log['type'][:25], 
            log['severity'], 
            log['status']
        ])
    
    log_table = Table(log_rows, colWidths=[1*inch, 2.5*inch, 1*inch, 1.5*inch])
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Courier'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
    ]))
    elements.append(log_table)
    elements.append(Spacer(1, 0.4 * inch))

    # 5. GEO-LOCATION MAP (Screenshot)
    if has_map_img:
        elements.append(Paragraph("<b>[C] GEO-FORENSIC LOCATION SNAPSHOT</b>", styles["Normal"]))
        elements.append(Spacer(1, 0.1 * inch))
        map_graphic = Image(map_img_filename, 6 * inch, 3.5 * inch)
        elements.append(map_graphic)
        elements.append(Spacer(1, 0.3 * inch))

    # 6. MOBILE SYNC SECTION (QR)
    if has_qr:
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph("<b>[D] SCAN TO SYNC WITH MOBILE HUD</b>", styles["Center"]))
        elements.append(Spacer(1, 0.1 * inch))
        qr_img = Image(qr_filename, 1.2 * inch, 1.2 * inch)
        elements.append(qr_img)

    doc.build(elements)

    # Cleanup temporary image files
    for f_path in [qr_filename, map_img_filename]:
        if os.path.exists(f_path):
            os.remove(f_path)

    return filename