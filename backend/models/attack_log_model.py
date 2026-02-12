from database import get_db

def log_attack(user_id, reason):
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO attack_logs(user_id, reason)
        VALUES (%s,%s)
    """, (user_id, reason))
    db.commit()
