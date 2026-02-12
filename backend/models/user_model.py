from database import get_db

def get_user(username):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    return cur.fetchone()
