from database import get_db

def log_login(user_id, ip, location, device, status):
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO login_logs(user_id, ip_address, location, device, status)
        VALUES (%s,%s,%s,%s,%s)
    """, (user_id, ip, location, device, status))
    db.commit()
