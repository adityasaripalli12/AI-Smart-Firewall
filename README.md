# AI Smart Firewall

## Overview
This is an AI-assisted smart firewall and security monitoring system designed to detect abnormal or malicious traffic and trigger automated defensive responses.

## Key Features
- AI-based anomaly detection
- Traffic monitoring
- Attack classification/detection
- Suspicious IP detection
- IP blocking
- Automated firewall response
- Honeypot redirection
- Backup server activation
- Security logs
- Severity classification
- OTP-protected administrative actions (Twilio OTP)
- PDF report generation (SOC reports)
- IP tracking
- Dashboard
- Attack simulation
- Real-time monitoring

## Architecture
```text
User/Traffic
      ↓
Traffic Monitoring
      ↓
AI Detection Layer
      ↓
Threat Classification
      ↓
Firewall Response Engine
      ↓
Block / Isolate / Honeypot / Backup
      ↓
Logging & Reporting
      ↓
Security Dashboard
```

## Technology Stack
- Python
- Flask
- Scikit-learn
- NumPy
- Twilio
- HTML
- CSS
- JavaScript
- ReportLab

## Project Structure
```text
AI-Smart-Firewall/
├── ai_detector.py
├── enhancements.py
├── firewall.py
├── honeypot.py
├── main.py
├── otp_service.py
├── report_generator.py
├── traffic_generator.py
├── requirements.txt
├── .gitignore
├── .env.example
├── static/
└── templates/
```

## Installation

Run these Windows PowerShell commands:

```powershell
git clone https://github.com/adityasaripalli12/AI-Smart-Firewall.git
cd AI-Smart-Firewall

# Create virtual environment
python -m venv venv

# Activate
.\venv\Scripts\Activate.ps1

# Install requirements
python -m pip install -r requirements.txt
```

## Environment Configuration

Create a `.env` file from the provided `.env.example`:

```powershell
cp .env.example .env
```

**CRITICAL:** Real credentials must never be committed to GitHub. Edit the `.env` file to include your actual Twilio keys, secret keys, and passwords.

## Default Credentials

For testing and evaluation purposes, you can use the following default credentials to access the admin dashboard:

- **Admin Username:** `stark_admin`
- **Admin Password:** `stark@123`
- **Secure Access Key (for resets):** `omega@777`

## Local Run

To run the application locally for development:

```powershell
python main.py
```
The application will be accessible at `http://127.0.0.1:5000` (or whichever port is assigned).

## Production Run

For production deployment, use Gunicorn (or another WSGI server):

```powershell
gunicorn main:app
```

## Security Notes
- **Never commit credentials** (like API keys, passwords) to version control.
- Use **environment variables** for all secrets.
- Protect administrative endpoints using strong passwords and OTPs.
- Use **HTTPS** in production to encrypt traffic.
- Restrict firewall controls to authorized personnel.
- Do not expose test or honeypot systems unnecessarily to public networks.
- Use the project only in authorized environments.

## Disclaimer
This project is intended for authorized security testing, defensive research, education, and controlled environments only.
