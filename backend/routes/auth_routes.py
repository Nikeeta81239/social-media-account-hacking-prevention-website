# backend/routes/auth_routes.py

from flask import Blueprint, request, jsonify
from database import get_db
from security.jwt_auth import generate_jwt
from security.password_hashing import check_password
from utils.otp_service import generate_otp, verify_otp
from utils.email_service import send_otp_email

from ai_ml.feature_extraction import extract_features
from ai_ml.risk_scoring import predict_risk
from ai_ml.explainable_ai import generate_xai_explanation

auth_bp = Blueprint("auth", __name__)


# ================= LOGIN =================
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")
    
    # Module 2: Capture device and location info (Simulated)
    device = data.get("device", "Unknown Device")
    location = data.get("location", "Unknown Location")

    db = get_db()
    cur = db.cursor(dictionary=True)

    # Module 1: Get user
    cur.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email, role))
    user = cur.fetchone()

    print(f"[DEBUG] Login attempt: {email}, Role requested: {role}, User found: {True if user else False}")

    if not user:
        cur.close()
        db.close()
        return jsonify({"message": "User not found"}), 404

    user_id = user["id"]

    # Module 1: Check if blocked
    cur.execute("SELECT * FROM blocked_users WHERE user_id=%s", (user["id"],))
    blocked = cur.fetchone()

    if blocked:
        cur.close()
        db.close()
        return jsonify({
            "status": "blocked",
            "message": "Account is blocked"
        }), 403

    # Module 1: Password check
    if not check_password(password, user["password"]):
        # Safe access to failed_attempts (handle case where column might be missing)
        current_attempts = user.get("failed_attempts", 0)
        new_attempts = current_attempts + 1
        
        if new_attempts >= 5:
            cur.execute("INSERT INTO blocked_users (user_id, reason) VALUES (%s, %s)", 
                        (user_id, "Too many failed login attempts (Safe Limit Exceeded)"))
            try:
                cur.execute("UPDATE users SET failed_attempts=0 WHERE id=%s", (user_id,))
            except:
                pass 
            db.commit()
            cur.close()
            db.close()
            return jsonify({"status": "blocked", "message": "Account blocked due to 5 failed attempts"}), 403
        else:
            try:
                cur.execute("UPDATE users SET failed_attempts=%s WHERE id=%s", (new_attempts, user_id))
            except:
                pass
            db.commit()
            cur.close()
            db.close()
            return jsonify({"message": f"Invalid password. Attempt {new_attempts}/5"}), 401

    # Reset failed attempts on successful password check
    # But first, check if we need to force OTP due to previous failures (3rd attempt rule)
    force_otp = False
    if user.get("failed_attempts", 0) >= 2:
        force_otp = True
        print(f"[DEBUG] Forcing OTP for {email} due to success on attempt {user.get('failed_attempts', 0) + 1}")

    try:
        cur.execute("UPDATE users SET failed_attempts=0 WHERE id=%s", (user_id,))
    except:
        pass
    db.commit()

    # ================= ADMIN DIRECT LOGIN =================
    if role == "admin":
        token = generate_jwt(user["id"], user["role"])
        cur.execute("""
            INSERT INTO login_logs (user_id, ip_address, location, device, status, risk)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user["id"], request.remote_addr, location, device, "success", "low"))
        db.commit()
        cur.close()
        db.close()
        return jsonify({"role": "admin", "token": token}), 200

    # ================= USER RISK EVALUATION (Modules 3, 4, 6) =================
    # Module 3: Feature Extraction
    features = extract_features(user["id"], device, location, request.remote_addr)
    
    # Module 4: ML Prediction
    risk_result = predict_risk(features)
    risk_level = risk_result["level"]
    risk_score = risk_result["score"]
    action = risk_result["action"]

    # FORCE OTP if this was the 3rd+ attempt
    if force_otp:
        action = "OTP"
        risk_level = "MEDIUM"
        risk_score = max(risk_score, 50) # Boost risk score for audit

    print(f"[DEBUG] Risk Analysis for {email}: Score={risk_score}%, Level={risk_level}, Action={action}")

    # Module 5: Explainable AI (if suspicious)
    if risk_level != "LOW":
        xai_data = generate_xai_explanation(risk_score, features)
        cur.execute("""
            INSERT INTO xai_explanations 
            (user_id, event_type, risk_score, decision, top_reasons, what_if, trust_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, "LOGIN_ATTEMPT", risk_score, xai_data["decision"], 
              xai_data["top_reasons"], xai_data["what_if"], xai_data["trust_score"]))

    # Module 6: Risk-based Action
    if action == "BLOCK":
        cur.execute("INSERT INTO blocked_users (user_id, reason) VALUES (%s, %s)", 
                    (user_id, f"High Risk Detection ({risk_score}%)"))
        db.commit()
        cur.close()
        db.close()
        return jsonify({"status": "blocked", "message": f"Suspicious activity detected ({risk_score}%)"}), 403

    if action == "OTP":
        otp = generate_otp(user_id)
        if send_otp_email(email, otp):
            cur.execute("""
                INSERT INTO login_logs (user_id, ip_address, location, device, status, risk)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, request.remote_addr, location, device, "otp_pending", "medium"))
            db.commit()
            cur.close()
            db.close()
            return jsonify({"status": "otp_required", "user_id": user_id, "role": "user"}), 200
        else:
            cur.close()
            db.close()
            return jsonify({"message": "Failed to send OTP"}), 500

    # ALLOW - Direct Success
    token = generate_jwt(user_id, user["role"])
    cur.execute("""
        INSERT INTO login_logs (user_id, ip_address, location, device, status, risk)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (user_id, request.remote_addr, location, device, "success", "low"))
    db.commit()
    cur.close()
    db.close()
    return jsonify({"role": "user", "token": token, "user_id": user_id}), 200


# ================= VERIFY OTP =================
@auth_bp.route("/verify-otp", methods=["POST"])
def verify_user_otp():
    data = request.get_json()
    user_id = data.get("user_id")
    entered_otp = data.get("otp")

    success, message = verify_otp(user_id, entered_otp)
    if not success:
        return jsonify({"verified": False, "message": message}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT role FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    token = generate_jwt(user_id, user["role"])

    cur.execute("""
        UPDATE login_logs
        SET status='success'
        WHERE user_id=%s AND status='otp_pending'
        ORDER BY id DESC LIMIT 1
    """, (user_id,))

    db.commit()
    cur.close()
    db.close()
    return jsonify({"verified": True, "message": "Login successful", "token": token, "role": user["role"]}), 200
