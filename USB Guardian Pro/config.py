import os

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-security-dashboard-secret-key-1337!')
    
    # Base directories
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # SQLite Database configuration
    DATABASE = os.path.join(BASE_DIR, 'usb_guardian.db')
    
    # Folder to store screenshot and webcam captures
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    
    # Ensure upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Telegram Bot alert settings (mock/disabled by default, configurable in Settings)
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
    
    # Default sensitive file scan keywords
    SENSITIVE_KEYWORDS = [
        'password', 'passwd', 'confidential', 'secret', 'ssn', 
        'financial', 'creditcard', 'salary', 'tax', 'cvv', 'key.pem', 'id_rsa'
    ]
    
    # Risk calculation constants
    RISK_UNAUTHORIZED_USB = 40
    RISK_SENSITIVE_FILE_HIT = 25
    RISK_LOCKDOWN_VIOLATION = 80
    RISK_FAILED_LOGIN = 10
