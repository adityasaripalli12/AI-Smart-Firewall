import os
from flask import Flask
from config import Config
from database.db import init_db
from backend.auth import auth_bp
from backend.routes import routes_bp
from backend.api import api_bp
from PIL import Image, ImageDraw

def create_mock_images():
    """
    Programmatically generates placeholder incident files so the audit logs
    feed has real visual attachments (screenshots, webcam) to display.
    """
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    mock_files = {
        'mock_screenshot.jpg': ((20, 24, 33), 'INCIDENT SCREENSHOT\n\nUnauthorized payload injection attempt detected.\nRubber Ducky Script executed.\nProcess quarantined: cmd.exe (PID: 4892)'),
        'mock_webcam.jpg': ((10, 10, 15), 'ENDPOINT WEBCAM ACTIVE\n\nSilhouette User Capture (SOC-09)\nDevice Alert: BADUSB-666\nLocation: Zone 4 - R&D Lab'),
        'mock_screenshot_file.jpg': ((20, 24, 33), 'SENSITIVE DATA CLASSIFIER SCAN\n\nFile Name: passwords.xlsx\nPattern Match: Keyphrase "passwd"\nClassification: RESTRICTED DATA\nAction: Blocked insertion & reported.')
    }
    
    for filename, (bg_color, text) in mock_files.items():
        filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
        if not os.path.exists(filepath):
            # Create a 640x360 image
            img = Image.new('RGB', (640, 360), color=bg_color)
            draw = ImageDraw.Draw(img)
            
            # Draw background grid for a "cyber monitor" look
            for x in range(0, 640, 20):
                draw.line([(x, 0), (x, 360)], fill=(40, 48, 66))
            for y in range(0, 360, 20):
                draw.line([(0, y), (640, y)], fill=(40, 48, 66))
                
            # Draw neon border
            draw.rectangle([(5, 5), (635, 355)], outline=(0, 255, 136), width=2)
            
            # Draw crosshair target lines
            draw.line([(320, 0), (320, 360)], fill=(0, 210, 255), width=1)
            draw.line([(0, 180), (640, 180)], fill=(0, 210, 255), width=1)
            
            # Draw mock terminal text (multiline)
            draw.text((20, 25), text, fill=(0, 255, 136))
            
            # Save file
            img.save(filepath, "JPEG")
            print(f"[Init] Generated mock incident image: {filepath}")

def create_app():
    # Flask app instantiation with specific template and static paths
    app = Flask(
        __name__, 
        template_folder=os.path.join(Config.BASE_DIR, 'dashboard', 'templates'),
        static_folder=os.path.join(Config.BASE_DIR, 'static')
    )
    app.config.from_object(Config)
    
    # Initialize SQLite Database and seed tables
    with app.app_context():
        init_db()
        create_mock_images()
        
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(routes_bp)
    app.register_blueprint(api_bp)
    
    return app

if __name__ == '__main__':
    app = create_app()
    # Run the application
    print("\n=======================================================")
    print("USB Guardian Pro - Enterprise Cybersecurity Dashboard")
    print("Dashboard URL: http://127.0.0.1:5000/")
    print("Credentials:")
    print("  - Admin: admin / admin123")
    print("  - Employee: employee / employee123")
    print("=======================================================\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
