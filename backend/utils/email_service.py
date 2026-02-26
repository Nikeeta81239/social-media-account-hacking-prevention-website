# backend/utils/email_service.py

import smtplib
from email.message import EmailMessage
from config import Config

def send_otp_email(to_email, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Your Login OTP - AI Cyber Shield"
        msg["From"] = Config.SMTP_EMAIL
        msg["To"] = to_email

        msg.set_content(f"""
Hello,

Your One-Time Password (OTP) is:

OTP: {otp}

This OTP is valid for 2 minutes.

If this wasn't you, please contact admin immediately.

— AI Cyber Shield
""")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(Config.SMTP_EMAIL, Config.SMTP_PASSWORD)
            server.send_message(msg)

        print("[SUCCESS] OTP sent successfully to", to_email)
        return True

    except Exception as e:
        print("[ERROR] Email sending failed:", e)
        return False

def send_security_alert(to_email, location, device, time, ip_address, primary_url, network_url, token):
    try:
        msg = EmailMessage()
        msg["Subject"] = "🚨 ACTION REQUIRED: Verify Your Identity"
        msg["From"] = Config.SMTP_EMAIL
        msg["To"] = to_email

        # Normalize URLs
        # Use 127.0.0.1 instead of localhost for better browser compatibility
        safe_primary = primary_url.replace("localhost", "127.0.0.1").rstrip('/')
        network_url = network_url.rstrip('/')
        
        # HTML Version for Buttons
        html_content = f"""
        <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f1f5f9; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 40px; border-radius: 16px; border: 1px solid #e2e8f0; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);">
                <div style="text-align: center; margin-bottom: 30px; border-bottom: 2px solid #f1f5f9; padding-bottom: 20px;">
                    <h1 style="color: #0f172a; margin: 0; font-size: 26px; letter-spacing: -0.025em;">Security Identity Verification</h1>
                    <p style="color: #64748b; font-size: 16px; margin-top: 8px;">AI-Powered Behavioral Monitoring System</p>
                </div>
                
                <p style="color: #334155; font-size: 16px; line-height: 1.6; text-align: center;"><b>A new login attempt was detected.</b><br>To allow access, please select your current device below:</p>
                
                <div style="background-color: #eff6ff; padding: 25px; border-radius: 12px; margin: 25px 0; border: 1px solid #bfdbfe;">
                    <p style="margin: 0 0 10px 0; color: #1e40af;"><b>📍 Attempt Location:</b> {location}</p>
                    <p style="margin: 0 0 10px 0; color: #1e40af;"><b>💻 Device Signature:</b> {device}</p>
                    <p style="margin: 0; color: #1e40af;"><b>🌐 Source IP:</b> {ip_address}</p>
                </div>
                
                <div style="text-align: center; margin: 35px 0;">
                    <p style="color: #0f172a; font-weight: 700; margin-bottom: 20px; font-size: 18px;">Was this you? (SELECT DEVICE)</p>
                    
                    <a href="http://127.0.0.1:8080/api/confirm-reset?token={token}" 
                       style="display: block; background-color: #06b6d4; color: white; padding: 16px; text-decoration: none; border-radius: 10px; font-weight: bold; font-size: 16px; margin-bottom: 12px; box-shadow: 0 4px 6px -1px rgba(6, 182, 212, 0.2);">
                       🖥️ YES, LOG IN ON THIS PC
                    </a>

                    <a href="{network_url}/api/confirm-reset?token={token}" 
                       style="display: block; background-color: #0ea5e9; color: white; padding: 16px; text-decoration: none; border-radius: 10px; font-weight: bold; font-size: 16px; margin-bottom: 25px; box-shadow: 0 4px 6px -1px rgba(14, 165, 233, 0.2);">
                       📱 YES, LOG IN ON MY PHONE
                    </a>
                    
                    <div style="border-top: 1px solid #f1f5f9; padding-top: 25px; margin-top: 25px;">
                        <p style="color: #64748b; font-size: 14px; margin-bottom: 15px; text-align: center;"><b>If you do not recognize this attempt:</b></p>
                        
                        <a href="http://127.0.0.1:8080/api/deny-reset?email={to_email}" 
                           style="display: block; color: #ef4444; text-decoration: none; border: 2px solid #fee2e2; padding: 16px; border-radius: 10px; font-weight: 700; font-size: 16px; background-color: #fffafc; margin-bottom: 10px; text-align: center;">
                           🚨 NO, SECURE MY ACCOUNT (This PC)
                        </a>

                        <a href="{network_url}/api/deny-reset?email={to_email}" 
                           style="display: block; color: #ef4444; text-decoration: none; border: 2px solid #fee2e2; padding: 16px; border-radius: 10px; font-weight: 700; font-size: 16px; background-color: #fffafc; text-align: center;">
                           🚨 NO, SECURE MY ACCOUNT (From Phone)
                        </a>
                    </div>
                </div>
                
                <div style="border-top: 1px solid #e2e8f0; margin-top: 40px; padding-top: 20px; text-align: center;">
                    <p style="font-size: 12px; color: #94a3b8; margin: 0;">
                        Security Alert ID: {token[:8]}... | Registered IP: {ip_address}
                    </p>
                    <p style="font-size: 11px; color: #cbd5e1; margin-top: 5px;">
                        © 2026 AI Cyber Shield. Admin alerted on every flag.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Fallback text version
        text_content = f"""
ACTION REQUIRED: Verify your identity.

Attempt Details:
- Location: {location}
- Device: {device}
- IP: {ip_address}

Verification Links:
PC/Local: http://127.0.0.1:8080/api/confirm-reset?token={token}
Mobile/Device: {network_url}/api/confirm-reset?token={token}
"""
        msg.set_content(text_content)
        msg.add_alternative(html_content, subtype='html')

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(Config.SMTP_EMAIL, Config.SMTP_PASSWORD)
            server.send_message(msg)

        print(f"[SUCCESS] Security alert sent to {to_email}")
        return True

    except Exception as e:
        print(f"[ERROR] Security alert email failed: {e}")
        return False
def send_admin_security_alert(user_email, reason):
    try:
        msg = EmailMessage()
        msg["Subject"] = "🚨 IMMEDIATE ATTENTION: User Reported Unauthorized Access"
        msg["From"] = Config.SMTP_EMAIL
        msg["To"] = Config.SMTP_EMAIL # Alerting the admin email configured
        
        msg.set_content(f"""
SECURITY ALERT FOR ADMINISTRATOR:
        
A user has just reported an unauthorized login attempt and initiated the 'Secure My Account' protocol.
        
User Email: {user_email}
Reason Flagged: {reason}
Timestamp: {datetime.datetime.now()}
        
ACTION REQUIRED:
1. Review the user's recent login logs.
2. Monitor for further suspicious activity from this user's IP range.
3. The account has already been automatically blocked.
        
— AI Cyber Shield Security Engine
""")
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(Config.SMTP_EMAIL, Config.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Admin alert failed: {e}")
        return False

import datetime
