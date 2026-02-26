import socket
import datetime
import json
import jwt
from flask import Blueprint, request, jsonify
from database import get_db
from security.jwt_auth import generate_jwt
from security.password_hashing import check_password, hash_password
from utils.otp_service import generate_otp, verify_otp
from utils.email_service import send_otp_email, send_security_alert
from ai_ml.feature_extraction import extract_features
from ai_ml.risk_scoring import predict_risk
from ai_ml.explainable_ai import generate_xai_explanation
from config import Config

def get_machine_ip():
    """Returns the most likely local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Using a public DNS IP to trigger the routing table
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
        s.close()
    except Exception:
        # Fallback to a broader search
        try:
            IP = socket.gethostbyname(socket.gethostname())
        except:
            IP = '127.0.0.1'
    return IP

auth_bp = Blueprint("auth", __name__)


# ================= LOGIN =================
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid request payload"}), 400
        
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")
    
    if not email or not password or not role:
        return jsonify({"message": "Email, password, and role are required"}), 400
    
    try:
        # Module 2: Capture device, location, and IP info (from frontend or request)
        device = data.get("device", "Unknown Device")
        location = data.get("location", "Unknown Location")
        ip = data.get("ip", request.remote_addr)

        db = get_db()
        cur = db.cursor(dictionary=True)

        # Module 1: Get user
        cur.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email, role))
        user = cur.fetchone()

        if not user:
            cur.close()
            db.close()
            return jsonify({"message": "User not found"}), 404

        user_id = user["id"]
        
        # ── ADMIN BYPASS ──
        if user['role'] == 'admin':
            if check_password(password, user["password"]):
                token = generate_jwt(user_id, user["role"])
                cur.execute("UPDATE users SET failed_attempts=0 WHERE id=%s", (user_id,))
                db.commit()
                cur.close()
                db.close()
                return jsonify({
                    "status": "success",
                    "token": token,
                    "role": user["role"],
                    "user_id": user_id,
                    "message": "Welcome, Administrator. Full access granted."
                }), 200
        
        current_attempts = user.get("failed_attempts", 0)
        
        # Check if user is currently blocked
        cur.execute("SELECT * FROM blocked_users WHERE user_id=%s ORDER BY blocked_time DESC LIMIT 1", (user_id,))
        blocked_entry = cur.fetchone()

        is_currently_blocked = False
        time_left = 30 # Default
        if blocked_entry:
            blocked_time = blocked_entry['blocked_time']
            diff = (datetime.datetime.now() - blocked_time).total_seconds()
            if diff < 30:
                is_currently_blocked = True
                time_left = 30 - int(diff)

        # Module 1: Password check
        is_password_correct = check_password(password, user["password"])
        
        # --- WRONG PASSWORD HANDLING ---
        if not is_password_correct:
            new_attempts = current_attempts + 1
            cur.execute("UPDATE users SET failed_attempts=%s WHERE id=%s", (new_attempts, user_id))
            db.commit()

            if is_currently_blocked:
                cur.close()
                db.close()
                return jsonify({
                    "status": "blocked",
                    "message": f"⚠ Access Restricted. Your account is temporarily blocked for suspicious activity.",
                    "time_left": time_left
                }), 403

            if new_attempts >= 5:
                cur.execute("INSERT INTO blocked_users (user_id, reason) VALUES (%s, %s)", (user_id, "Max failed attempts reached"))
                db.commit()
                cur.close()
                db.close()
                return jsonify({
                    "status": "blocked", 
                    "message": "⚠ Account Blocked. Excessive failed attempts detected. Access restricted for 30 seconds.",
                    "time_left": 30
                }), 403
            
            cur.close()
            db.close()
            return jsonify({"status": "failed", "message": f"Invalid credentials. Attempt {new_attempts}/5."}), 401

        # --- CORRECT PASSWORD HANDLING ---
        
        # Module 3: Feature Extraction & Risk Prediction
        features = extract_features(user_id, device, location, ip)
        features["failed_attempts"] = current_attempts
        risk_result = predict_risk(features)
        risk_score = risk_result["score"]
        
        # Module 4: Explainable AI
        xai_data = generate_xai_explanation(risk_score, features)
        cur.execute("""
            INSERT INTO xai_explanations 
            (user_id, event_type, risk_score, decision, top_reasons, what_if, trust_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, "LOGIN_ATTEMPT", risk_score, xai_data["decision"], 
              json.dumps({
                  "reason": xai_data["reason"],
                  "suggested_action": xai_data["suggested_action"],
                  "dynamic_analysis": xai_data["dynamic_analysis"],
                  "feature_weights": xai_data["feature_weights"]
              }), xai_data["what_if"], xai_data["trust_score"]))
        db.commit()

        # --- HIGH RISK (>= 70%) or ACTIVE BLOCK ---
        # If currently blocked (within 30s), reject immediately.
        # If NOT currently blocked but high risk, block ONLY if NOT in recovery mode.
        has_expired_block = (blocked_entry and not is_currently_blocked)
        
        if is_currently_blocked or (risk_score >= 70 and not has_expired_block):
            # If this is a FRESH high risk login (not recovery), insert a new block
            if not is_currently_blocked and risk_score >= 70:
                 cur.execute("INSERT INTO blocked_users (user_id, reason) VALUES (%s, %s)", 
                            (user_id, f"High Risk Incident: {xai_data['reason'][:100]}"))
                 db.commit()
            
            # Log the blocked attempt
            cur.execute("""
                INSERT INTO login_logs (user_id, ip_address, location, device, status, risk)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, ip, location, device, "Blocked", "high"))
            db.commit()
            
            cur.close()
            db.close()
            return jsonify({
                "status": "blocked",
                "risk_score": risk_score,
                "reason": xai_data["reason"],
                "message": "⚠ Access Restricted. Due to high-risk patterns, access is temporarily locked for 30 seconds.",
                "time_left": time_left if is_currently_blocked else 30,
                "xai": xai_data
            }), 403

        # --- RECOVERY or MEDIUM RISK (OTP REQUIRED) ---
        # We reach here if:
        # 1. Risk is medium (31-69)
        # 2. Risk is high (>=70) but the user's 30s block just EXPIRED (Recovery Mode)
        if risk_score >= 31 or has_expired_block:
            otp = generate_otp(user_id)
            if send_otp_email(email, otp):
                cur.execute("""
                    INSERT INTO login_logs (user_id, ip_address, location, device, status, risk)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (user_id, ip, location, device, "otp_pending", "medium"))
                db.commit()
                cur.close()
                db.close()
                return jsonify({
                    "status": "otp_required",
                    "user_id": user_id,
                    "role": user["role"],
                    "message": xai_data["suggested_action"],
                    "reason": xai_data["reason"],
                    "xai": xai_data
                }), 200

        # --- NORMAL RISK (< 31%) ---
        cur.execute("UPDATE users SET failed_attempts=0 WHERE id=%s", (user_id,))
        db.commit()
        
        token = generate_jwt(user_id, user["role"])
        cur.execute("""
            INSERT INTO login_logs (user_id, ip_address, location, device, status, risk)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, ip, location, device, "success", "low"))
        db.commit()
        cur.close()
        db.close()
        return jsonify({
            "verified": True, 
            "token": token, 
            "role": user["role"], 
            "user_id": user_id,
            "xai": xai_data
        }), 200

    except Exception as e:
        print(f"CRITICAL LOGIN ERROR: {e}")
        return jsonify({
            "status": "error",
            "message": f"Server encountered an error during login: {str(e)}"
        }), 500


# ================= FORGOT PASSWORD =================
@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    device = data.get("device", "Unknown Device")
    location = data.get("location", "Unknown Location")
    ip = data.get("ip", request.remote_addr)
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    
    if not user:
        cur.close()
        db.close()
        return jsonify({"message": "If this email is registered, a security alert has been sent."}), 200

    # Sending Security Alert Email
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # --- DUAL URL STRATEGY ---
    # Use the same host the user is currently using (best for same-machine testing)
    primary_url = request.host_url.rstrip('/')
    
    # Detect the actual network IP (best for mobile devices/other PCs)
    local_ip = get_machine_ip()
    port = request.host.split(':')[-1] if ':' in request.host else '5000'
    network_url = f"http://{local_ip}:{port}"

    # Generate a secure reset token (valid for 15 mins)
    reset_token = jwt.encode({
        "reset_email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }, Config.JWT_SECRET, algorithm="HS256")
    
    # --- Debugging ---
    print(f"\n[DEBUG] Recovery Links Generated:")
    print(f"[PC/Local]:    {primary_url}/api/confirm-reset?token={reset_token}")
    print(f"[Network IP]:  {network_url}/api/confirm-reset?token={reset_token}")
    print(f"----------------------------------\n")

    alert_sent = send_security_alert(
        email, 
        location=location, 
        device=device, 
        time=now,
        ip_address=ip,
        primary_url=primary_url,
        network_url=network_url,
        token=reset_token
    )

    if alert_sent:
        cur.close()
        db.close()
        return jsonify({"message": "Security alert sent successfully. Check your email to confirm identity."}), 200
    
    cur.close()
    db.close()
    return jsonify({"message": "Failed to send security alert."}), 500

# ================= CONFIRM / DENY LINKS =================
@auth_bp.route("/confirm-reset", methods=["GET"])
def confirm_reset():
    token = request.args.get("token")
    if not token:
        return """
        <body style="font-family:sans-serif; text-align:center; padding:50px;">
            <h1 style="color:#ef4444;">Invalid Request</h1>
            <p>Verification token is missing.</p>
        </body>
        """, 400
    
    try:
        data = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
        email = data["reset_email"]
        
        return f"""
        <html>
        <head>
            <title>Reset Password | AI Cyber Shield</title>
            <style>
                body {{ font-family: 'Poppins', sans-serif; background: #020617; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                .box {{ background: #0f172a; padding: 40px; border-radius: 12px; border: 1px solid #1e293b; width: 100%; max-width: 400px; text-align: center; }}
                input {{ width: 100%; padding: 12px; margin: 15px 0; background: #020617; border: 1px solid #334155; color: white; border-radius: 6px; box-sizing: border-box; }}
                button {{ width: 100%; padding: 12px; background: #06b6d4; border: none; color: white; font-weight: bold; border-radius: 6px; cursor: pointer; }}
                button:hover {{ background: #22d3ee; }}
            </style>
        </head>
        <body>
            <div class="box">
                <h2 style="color:#06b6d4;">Reset Password</h2>
                <p>Enter a new password for <b>{email}</b></p>
                <form action="/api/reset-password-final" method="POST">
                    <input type="hidden" name="token" value="{token}">
                    <input type="password" name="new_password" placeholder="New Password" required minlength="6">
                    <button type="submit">Update Password</button>
                </form>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        return f"""
        <body style="font-family:sans-serif; text-align:center; padding:50px;">
            <h1 style="color:#ef4444;">Verification Failed</h1>
            <p>The link may have expired or is invalid. Please request a new one.</p>
        </body>
        """, 401

@auth_bp.route("/reset-password-final", methods=["POST"])
def reset_password_final():
    token = request.form.get("token")
    new_password = request.form.get("new_password")
    
    try:
        data = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
        email = data["reset_email"]
        
        hashed_pw = hash_password(new_password)
        
        db = get_db()
        cur = db.cursor()
        cur.execute("UPDATE users SET password=%s, failed_attempts=0 WHERE email=%s", (hashed_pw, email))
        db.commit()
        cur.close()
        db.close()
        
        # Determine the root login URL dynamically
        root_url = request.host_url
        
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Poppins', sans-serif; background: #020617; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                .box {{ background: #0f172a; padding: 40px; border-radius: 12px; border: 1px solid #1e293b; width: 100%; max-width: 400px; text-align: center; }}
                .btn {{ display: inline-block; width: 100%; padding: 12px; background: #06b6d4; border: none; color: white; font-weight: bold; border-radius: 6px; text-decoration: none; margin-top: 20px; }}
                .btn:hover {{ background: #22d3ee; }}
            </style>
        </head>
        <body>
            <div class="box">
                <h1 style="color:#10b981;">Password Updated!</h1>
                <p>Your credentials for <b>{email}</b> have been secured. You can now login with your new password.</p>
                <a href="{root_url}" class="btn">Return to Login</a>
            </div>
        </body>
        </html>
        """
    except:
        return "Invalid or expired token.", 401

@auth_bp.route("/deny-reset", methods=["GET"])
def deny_reset():
    email = request.args.get("email")
    if not email:
        return "Email missing", 400
        
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    
    if user:
        user_id = user["id"]
        # 1. Block the account immediately (Security Action)
        cur.execute("INSERT INTO blocked_users (user_id, reason) VALUES (%s, %s)", 
                   (user_id, "User flagged unauthorized login (Secure My Account)"))
        
        # 2. Generate and Send OTP for Recovery
        otp = generate_otp(user_id)
        send_otp_email(email, otp)
        
        # 3. Notify Admin (Requirement: get the gmail to real admin)
        from utils.email_service import send_admin_security_alert
        send_admin_security_alert(email, "Unauthorized reset/login attempt flagged by user.")
        
        db.commit()
        cur.close()
        db.close()
        
        # 3. Redirect to the specialized Security Recovery page WITH a premium landing UI
        admin_email = Config.SMTP_EMAIL
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Poppins', sans-serif; background: #020617; color: white; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }}
                .card {{ background: #0f172a; border: 1px solid #ef4444; padding: 40px; border-radius: 20px; text-align: center; max-width: 450px; box-shadow: 0 0 50px rgba(239, 68, 68, 0.2); }}
                .icon {{ font-size: 50px; color: #ef4444; margin-bottom: 20px; }}
                h1 {{ color: #ef4444; margin-bottom: 15px; font-size: 24px; }}
                p {{ color: #94a3b8; line-height: 1.6; margin-bottom: 25px; }}
                .btn-group {{ display: flex; flex-direction: column; gap: 12px; }}
                .btn {{ display: block; padding: 14px; border-radius: 10px; text-decoration: none; font-weight: bold; transition: 0.3s; }}
                .btn-recovery {{ background: #06b6d4; color: white; }}
                .btn-admin {{ border: 2px solid #ef4444; color: #ef4444; }}
                .btn-recovery:hover {{ background: #22d3ee; }}
                .btn-admin:hover {{ background: rgba(239,68,68,0.1); }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon">🚨</div>
                <h1>Account Secured!</h1>
                <p>We've restricted access to <b>{email}</b> and blocked the unauthorized attempt. An OTP has been sent for you to reclaim your account.</p>
                
                <div class="btn-group">
                    <a href="/security-recovery?email={email}&user_id={user_id}" class="btn btn-recovery">Verify My Identity Now</a>
                    <a href="mailto:{admin_email}?subject=Urgent: Unauthorized Account Activity Report - {email}&body=Hello Admin, I just flagged an unauthorized login attempt on my account ({email}). Please review my logs and ensure my account is fully protected." class="btn btn-admin">📧 Send Message to Admin</a>
                </div>
            </div>
        </body>
        </html>
        """
    
    cur.close()
    db.close()
    return "User not found", 404


# ================= VERIFY OTP =================
@auth_bp.route("/verify-otp", methods=["POST"])
def verify_user_otp():
    data = request.get_json()
    user_id = data.get("user_id")
    entered_otp = data.get("otp")

    db = get_db()
    cur = db.cursor(dictionary=True)

    # Note: We NO LONGER hard-block here because OTP is the recovery path for blocked users.
    # We only check if the user exists.
    cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close()
        db.close()
        return jsonify({"verified": False, "message": "User not found"}), 404

    success, message = verify_otp(user_id, entered_otp)
    if not success:
        cur.close()
        db.close()
        return jsonify({"verified": False, "message": message}), 400

    token = generate_jwt(user_id, user["role"])

    # Reset failed_attempts
    cur.execute("UPDATE users SET failed_attempts=0 WHERE id=%s", (user_id,))
    
    # UNBLOCK user upon successful OTP verification (Identity Recovery)
    cur.execute("DELETE FROM blocked_users WHERE user_id=%s", (user_id,))

    cur.execute("""
        UPDATE login_logs
        SET status='success'
        WHERE user_id=%s AND status IN ('otp_pending','otp_pending_fail')
        ORDER BY id DESC LIMIT 1
    """, (user_id,))

    # Fetch the latest XAI for this login event to show on dashboard after redirect
    cur.execute("""
        SELECT * FROM xai_explanations 
        WHERE user_id=%s 
        ORDER BY created_at DESC LIMIT 1
    """, (user_id,))
    xai_row = cur.fetchone()
    xai_data = None
    if xai_row:
        import json
        try:
            top_reasons = json.loads(xai_row["top_reasons"])
            xai_data = {
                "decision": xai_row["decision"],
                "risk_score": xai_row["risk_score"],
                "reason": top_reasons.get("reason"),
                "suggested_action": top_reasons.get("suggested_action"),
                "dynamic_analysis": top_reasons.get("dynamic_analysis"),
                "trust_score": xai_row["trust_score"]
            }
        except:
            xai_data = {"decision": xai_row["decision"], "risk_score": xai_row["risk_score"]}

    db.commit()
    cur.close()
    db.close()
    return jsonify({
        "verified": True, 
        "message": "Login successful", 
        "token": token, 
        "role": user["role"],
        "user_id": user_id,
        "xai": xai_data
    }), 200


# ================= RESEND OTP =================
@auth_bp.route("/resend-otp", methods=["POST"])
def resend_user_otp():
    data = request.get_json()
    user_id = data.get("user_id")

    db = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT email FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()

    if not user:
        cur.close()
        db.close()
        return jsonify({"message": "User not found"}), 404

    otp = generate_otp(user_id)
    if send_otp_email(user["email"], otp):
        cur.close()
        db.close()
        return jsonify({"message": "OTP resent successfully"}), 200
    else:
        cur.close()
        db.close()
        return jsonify({"message": "Failed to resend OTP"}), 500

