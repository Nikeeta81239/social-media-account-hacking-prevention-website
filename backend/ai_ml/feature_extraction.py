
import datetime
import math
from database import get_db

def extract_features(user_id, device, location, ip_address):
    """
    Extracts deviation scores by comparing current activity against historical baseline.
    Returns a normalized feature vector (0 to 1) for CatBoost.
    Uses only Python built-in datetime — no external timezone packages required.
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Get last 20 SUCCESSFUL historical login logs for this user (behavioral baseline)
    cursor.execute("""
        SELECT device, location, ip_address, login_time
        FROM login_logs
        WHERE user_id=%s AND status='success'
        ORDER BY login_time DESC
        LIMIT 20
    """, (user_id,))
    history = cursor.fetchall()

    # Get ALL recent login attempts (success + failed) for frequency analysis
    # This correctly captures brute-force / burst patterns
    cursor.execute("""
        SELECT login_time, status
        FROM login_logs
        WHERE user_id=%s
        ORDER BY login_time DESC
        LIMIT 50
    """, (user_id,))
    all_logins = cursor.fetchall()

    # Count total failed attempts ever
    cursor.execute("""
        SELECT COUNT(*) as cnt FROM login_logs
        WHERE user_id=%s AND status NOT IN ('success')
    """, (user_id,))
    failed_row = cursor.fetchone()
    total_failed_ever = failed_row["cnt"] if failed_row else 0

    cursor.close()

    # Use UTC as consistent server-side timestamp (no pytz needed — datetime.utcnow() is naive UTC)
    current_time_utc = datetime.datetime.utcnow()
    current_hour = current_time_utc.hour
    login_time_str = current_time_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Helper: strip timezone info (make naive) for comparison ──
    def to_naive_utc(dt):
        """Convert any datetime to naive UTC for comparison."""
        if dt is None:
            return current_time_utc
        if isinstance(dt, datetime.datetime):
            if dt.tzinfo is not None:
                # Remove tzinfo — treat DB datetimes as UTC naive
                return dt.replace(tzinfo=None)
            return dt
        if isinstance(dt, datetime.date):
            return datetime.datetime(dt.year, dt.month, dt.day)
        return current_time_utc

    # ─────────────────────────────────────────────────────────────
    # Frequency counts from ALL logins (24h / 48h / 72h windows)
    # These windows use the current UTC time as reference
    # ─────────────────────────────────────────────────────────────
    logins_24h = 0
    logins_48h = 0
    logins_72h = 0
    for h in all_logins:
        lt = to_naive_utc(h["login_time"])
        diff_sec = (current_time_utc - lt).total_seconds()
        if diff_sec <= 86400:    # 24 hours
            logins_24h += 1
        if diff_sec <= 172800:   # 48 hours
            logins_48h += 1
        if diff_sec <= 259200:   # 72 hours
            logins_72h += 1

    if not history:
        # No successful history yet — all deviations default to 0 (new user)
        return {
            "time_deviation":      0.0,
            "location_deviation":  0.0,
            "device_deviation":    0.0,
            "frequency_deviation": 0.0,
            "history_count":       0,
            "total_failed_ever":   total_failed_ever,
            "frequency_counts": {
                "24h": logins_24h,
                "48h": logins_48h,
                "72h": logins_72h
            },
            "current_features": {
                "hour":           current_hour,
                "device":         device,
                "location":       location,
                "ip":             ip_address,
                "login_time_utc": login_time_str
            }
        }

    # ─────────────────────────────────────────────────────────────
    # 1. LOGIN TIME DEVIATION
    #    Based on last 10–20 successful login hours (circular mean)
    #    Circular averaging handles midnight wraparound correctly.
    # ─────────────────────────────────────────────────────────────
    hours = []
    for h in history:
        lt = to_naive_utc(h["login_time"])
        hours.append(lt.hour)

    if hours:
        # Circular mean: convert hours to radians on a 24h circle
        TWO_PI = 2 * math.pi
        sin_sum = sum(math.sin(TWO_PI * hr / 24) for hr in hours)
        cos_sum = sum(math.cos(TWO_PI * hr / 24) for hr in hours)
        avg_angle = math.atan2(sin_sum / len(hours), cos_sum / len(hours))
        avg_hour = (avg_angle * 24 / TWO_PI) % 24

        # Circular distance between current hour and average hour
        hour_diff = abs(current_hour - avg_hour)
        hour_diff = min(hour_diff, 24 - hour_diff)  # wrap around
        time_dev = min(hour_diff / 12.0, 1.0)        # normalize 0→1
    else:
        time_dev = 0.0

    # ─────────────────────────────────────────────────────────────
    # 2. LOCATION DEVIATION
    #    Binary: 0 if seen before, 1 if new location
    # ─────────────────────────────────────────────────────────────
    known_locations = set(h["location"] for h in history if h["location"])
    loc_dev = 0.0 if location in known_locations else 1.0

    # ─────────────────────────────────────────────────────────────
    # 3. DEVICE DEVIATION
    #    Binary: 0 if seen before, 1 if new device
    # ─────────────────────────────────────────────────────────────
    known_devices = set(h["device"] for h in history if h["device"])
    dev_dev = 0.0 if device in known_devices else 1.0

    # ─────────────────────────────────────────────────────────────
    # 4. FREQUENCY DEVIATION
    #    Compares current 24h login count to user's average daily rate
    #    Uses ALL logins (not just successes) to catch brute-force
    # ─────────────────────────────────────────────────────────────
    if len(history) >= 2:
        oldest = to_naive_utc(history[-1]["login_time"])
        newest = to_naive_utc(history[0]["login_time"])
        span_hours = max((newest - oldest).total_seconds() / 3600.0, 1.0)
        avg_logins_per_day = max(len(history) / (span_hours / 24.0), 1.0)
    else:
        avg_logins_per_day = 1.0

    freq_dev = min(abs(logins_24h - avg_logins_per_day) / max(avg_logins_per_day, 1.0), 1.0)

    return {
        "time_deviation":      round(float(time_dev), 3),
        "location_deviation":  float(loc_dev),
        "device_deviation":    float(dev_dev),
        "frequency_deviation": round(float(freq_dev), 3),
        "history_count":       len(history),
        "total_failed_ever":   total_failed_ever,
        "frequency_counts": {
            "24h": logins_24h,
            "48h": logins_48h,
            "72h": logins_72h
        },
        "current_features": {
            "hour":           current_hour,
            "device":         device,
            "location":       location,
            "ip":             ip_address,
            "login_time_utc": login_time_str
        }
    }
