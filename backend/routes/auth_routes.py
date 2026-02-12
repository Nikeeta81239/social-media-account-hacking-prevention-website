# backend/routes/auth_routes.py

from flask import Blueprint, request, jsonify
from database import get_db
from security.jwt_auth import generate_jwt
from security.password_hashing import check_password
from utils.otp_service import generate_otp, verify_otp
from utils.email_service import send_otp_email

auth_bp = Blueprint("auth", __name__)

# ================= LOGIN =================
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")

    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email, role))
    user = cur.fetchone()
    cur.close()
    db.close()

    if not user:
        return jsonify({"message": "User not found"}), 404

    if not check_password(password, user["password"]):
        return jsonify({"message": "Invalid password"}), 401

    # ================= ADMIN DIRECT LOGIN =================
    if role == "admin":
        token = generate_jwt(user["id"], user["role"])
        return jsonify({
            "role": "admin",
            "token": token
        }), 200

    # ================= USER → OTP =================
    otp = generate_otp(user["id"])
    email_sent = send_otp_email(email, otp)

    if not email_sent:
        return jsonify({"message": "Failed to send OTP"}), 500

    return jsonify({
        "status": "otp_required",
        "user_id": user["id"]
    }), 200


# ================= VERIFY OTP =================
@auth_bp.route("/verify-otp", methods=["POST"])
def verify_user_otp():
    data = request.get_json()
    user_id = data.get("user_id")
    entered_otp = data.get("otp")

    success, message = verify_otp(user_id, entered_otp)

    if not success:
        return jsonify({"message": message}), 400

    # Fetch user role from DB
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT role FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    cur.close()
    db.close()

    token = generate_jwt(user_id, user["role"])

    return jsonify({
        "message": "Login successful",
        "token": token,
        "role": user["role"]
    }), 200
