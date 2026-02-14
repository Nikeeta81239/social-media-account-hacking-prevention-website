from database import get_db

def add_failed_attempts_column():
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("ALTER TABLE users ADD COLUMN failed_attempts INT DEFAULT 0")
        db.commit()
        print("Column 'failed_attempts' added successfully.")
    except Exception as e:
        if "Duplicate column name" in str(e):
            print("Column 'failed_attempts' already exists.")
        else:
            print(f"Error: {e}")
    finally:
        cur.close()
        db.close()

if __name__ == "__main__":
    add_failed_attempts_column()
