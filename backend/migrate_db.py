from database import get_db
try:
    db = get_db()
    cur = db.cursor()
    # Check if column exists
    cur.execute("""
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_NAME = 'login_logs' 
        AND COLUMN_NAME = 'behavior_reason'
        AND TABLE_SCHEMA = (SELECT DATABASE())
    """)
    if cur.fetchone()[0] == 0:
        cur.execute("ALTER TABLE login_logs ADD COLUMN behavior_reason TEXT")
        db.commit()
        print("Successfully added behavior_reason column.")
    else:
        print("Column behavior_reason already exists.")
    cur.close()
    db.close()
except Exception as e:
    print(f"Migration failed: {e}")
