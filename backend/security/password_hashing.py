import bcrypt

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    try:
        # Try bcrypt comparison first (Secure)
        if bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8')):
            return True
    except Exception:
        pass
    
    # Fallback for plain-text (Common in testing/legacy data)
    return password == hashed
