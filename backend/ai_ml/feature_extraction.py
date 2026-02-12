import datetime
from database import get_db

def extract_features(user_id, device, location):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT device, location, login_time
        FROM login_logs
        WHERE user_id=%s
        ORDER BY login_time DESC
        LIMIT 5
    """, (user_id,))
    history = cursor.fetchall()

    hour = datetime.datetime.now().hour
    device_change = int(any(h["device"] != device for h in history))
    location_change = int(any(h["location"] != location for h in history))

    return {
        "login_hour": hour,
        "device_change": device_change,
        "location_change": location_change,
        "history_count": len(history)
    }
