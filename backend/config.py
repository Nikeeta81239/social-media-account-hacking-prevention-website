# backend/config.py

class Config:
    SECRET_KEY = "THIS_IS_A_VERY_STRONG_SECRET_KEY_32_CHARS_MINIMUM_2026"
    JWT_SECRET = "jwt-secret-key"
    GEMINI_API_KEY ="AIzaSyDcQuxMRFlcU_iwzkZ7AHCv8-hQz7Sort0"
    # ✅ GMAIL SMTP (USE APP PASSWORD)
    SMTP_EMAIL = "nikeetareddy81239@gmail.com"
    SMTP_PASSWORD = "dpsszjjbpcpudnvr"

    OTP_EXPIRY_SECONDS = 180 # 3 minutes

    DB_CONFIG = {
        "host": "localhost",
        "port": 3306,
        "user": "root",
        "password": "dbms123456789@#",
        "database": "ai_social_security"
    }
