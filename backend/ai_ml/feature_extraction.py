
import datetime
import numpy as np
from database import get_db

def extract_features(user_id, device, location, ip_address):
    """
    Extracts deviation scores by comparing current activity against historical baseline.
    Returns a normalized feature vector (0 to 1) for CatBoost.
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Get historical login logs for this user
    cursor.execute("""
        SELECT device, location, ip_address, login_time
        FROM login_logs
        WHERE user_id=%s AND status='success'
        ORDER BY login_time DESC
        LIMIT 20
    """, (user_id,))
    history = cursor.fetchall()
    cursor.close()

    current_time = datetime.datetime.now()
    current_hour = current_time.hour

    if not history:
        # No history: Default baseline (deviations = 0)
        return {
            "time_deviation": 0.0,
            "location_deviation": 0.0,
            "device_deviation": 0.0,
            "frequency_deviation": 0.0,
            "history_count": 0,
            "frequency_counts": {
                "24h": 0,
                "48h": 0,
                "72h": 0
            },
            "current_features": {
                "hour": current_hour,
                "device": device,
                "location": location,
                "ip": ip_address
            }
        }

    # 1. Login Time Deviation
    # Calculate average historical hour
    hours = [h["login_time"].hour for h in history]
    avg_hour = sum(hours) / len(hours)
    # Circular distance for hours (0-23)
    hour_diff = min(abs(current_hour - avg_hour), 24 - abs(current_hour - avg_hour))
    time_dev = min(hour_diff / 12, 1.0) # Normalized 0 to 1

    # 2. Location Deviation
    # Check if location has been seen before
    locations = set(h["location"] for h in history)
    loc_dev = 0.0 if location in locations else 1.0

    # 3. Device Deviation
    # Check if device has been seen before
    devices = set(h["device"] for h in history)
    dev_dev = 0.0 if device in devices else 1.0

    # 4. Frequency Deviation (Enhanced: 24/48/72h windows)
    logins_24h = sum(1 for h in history if (current_time - h["login_time"]).total_seconds() <= 86400)
    logins_48h = sum(1 for h in history if (current_time - h["login_time"]).total_seconds() <= 172800)
    logins_72h = sum(1 for h in history if (current_time - h["login_time"]).total_seconds() <= 259200)
    
    # Calculate average historical frequency (logins per 24h)
    # Based on total span of history
    span_hours = (history[0]["login_time"] - history[-1]["login_time"]).total_seconds() / 3600
    avg_logins_per_day = (len(history) / (span_hours / 24)) if span_hours > 0 else 1.0
    
    # Current frequency (mostly focused on 24h burst)
    current_freq = logins_24h
    freq_dev = min(abs(current_freq - avg_logins_per_day) / max(avg_logins_per_day, 1), 1.0)

    return {
        "time_deviation": round(float(time_dev), 3),
        "location_deviation": float(loc_dev),
        "device_deviation": float(dev_dev),
        "frequency_deviation": round(float(freq_dev), 3),
        "history_count": len(history),
        "frequency_counts": {
            "24h": logins_24h,
            "48h": logins_48h,
            "72h": logins_72h
        },
        "current_features": {
            "hour": current_hour,
            "device": device,
            "location": location,
            "ip": ip_address
        }
    }
