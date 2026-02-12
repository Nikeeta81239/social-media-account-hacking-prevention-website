# backend/utils/email_service.py

import smtplib
from email.message import EmailMessage
from config import Config

def send_otp_email(to_email, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "🔐 Your Login OTP – AI Cyber Shield"
        msg["From"] = Config.SMTP_EMAIL
        msg["To"] = to_email

        msg.set_content(f"""
Hello,

Your One-Time Password (OTP) is:

🔐 {otp}

This OTP is valid for 2 minutes.

If this wasn't you, please contact admin immediately.

— AI Cyber Shield
""")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(Config.SMTP_EMAIL, Config.SMTP_PASSWORD)
            server.send_message(msg)

        print("✅ OTP sent successfully to", to_email)
        return True

    except Exception as e:
        print("❌ Email sending failed:", e)
        return False
