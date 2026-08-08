import requests
import os
from database.db import get_db_connection

def send_telegram_alert(message, image_path=None):
    """
    Sends a security alert to a Telegram channel/chat.
    Fetches credentials dynamically from the SQLite settings table.
    """
    conn = get_db_connection()
    token_row = conn.execute("SELECT value FROM settings WHERE key = 'telegram_bot_token'").fetchone()
    chat_row = conn.execute("SELECT value FROM settings WHERE key = 'telegram_chat_id'").fetchone()
    conn.close()
    
    bot_token = token_row['value'] if token_row else ''
    chat_id = chat_row['value'] if chat_row else ''
    
    if not bot_token or not chat_id:
        print("[Telegram Alert] Bot Token or Chat ID not configured. Skipping notification.")
        return False
        
    try:
        # 1. Send the text message
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": f"⚠️ [USB Guardian Pro Alert]\n\n{message}",
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=5)
        
        if not response.ok:
            print(f"[Telegram Alert] Failed to send message: {response.text}")
            return False
            
        # 2. Upload image attachment if provided
        if image_path and os.path.exists(image_path):
            photo_url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
            with open(image_path, 'rb') as photo:
                files = {'photo': photo}
                photo_payload = {
                    "chat_id": chat_id,
                    "caption": "📸 Incident Capture Snapshot"
                }
                photo_res = requests.post(photo_url, data=photo_payload, files=files, timeout=10)
                if not photo_res.ok:
                    print(f"[Telegram Alert] Failed to send incident photo: {photo_res.text}")
                    
        return True
    except Exception as e:
        print(f"[Telegram Alert] Exception occurred: {e}")
        return False
