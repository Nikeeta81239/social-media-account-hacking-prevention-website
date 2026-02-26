# backend/routes/dashboard_routes.py

from flask import Blueprint, jsonify, request
from database import get_db
from security.jwt_auth import token_required

dashboard_bp = Blueprint("dashboard", __name__)


# ================= USER DASHBOARD DATA =================
@dashboard_bp.route("/dashboard-data", methods=["GET"])
@token_required()
def dashboard_data(user_id, role):
    # Note: user_id is passed from JWT. We can still allow manual override via query param if admin
    query_user_id = request.args.get("user_id")
    
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    # Check if current user is admin
    cur.execute("SELECT role FROM users WHERE id=%s", (user_id,))
    u_row = cur.fetchone()
    is_admin = (u_row and u_row["role"] == "admin")
    
    # If admin and query_user_id provided, use that. Otherwise use JWT user_id.
    target_id = query_user_id if (is_admin and query_user_id) else user_id

    # Guard: reject null / empty / literal-string-null user_id
    if not user_id or user_id in ("null", "undefined", "None", ""):
        return jsonify({
            "trustedDevices": 0, "suspiciousCount": 0, "newLocations": 0,
            "riskLevel": 0, "profileTrustScore": 100, "isFake": False,
            "recent": [], "error": "user_id missing"
        }), 200

    db = get_db()
    cur = db.cursor(dictionary=True)

    # Trusted devices count (distinct devices with 'success' status)
    cur.execute("""
        SELECT COUNT(DISTINCT device) as cnt FROM login_logs
        WHERE user_id=%s AND status='success'
    """, (target_id,))
    row = cur.fetchone()
    trusted_devices = row["cnt"] if row else 0

    # Suspicious login count (Blocked or OTP Pending)
    cur.execute("""
        SELECT COUNT(*) as cnt FROM login_logs
        WHERE user_id=%s AND (status='Suspicious' OR status='Blocked' OR status='otp_pending' OR risk IN ('medium', 'high'))
    """, (target_id,))
    row = cur.fetchone()
    suspicious_count = row["cnt"] if row else 0

    # New locations count (distinct locations)
    cur.execute("""
        SELECT COUNT(DISTINCT location) as cnt FROM login_logs
        WHERE user_id=%s
    """, (target_id,))
    row = cur.fetchone()
    new_locations = row["cnt"] if row else 0

    # Risk level calculation
    total_logins_q = "SELECT COUNT(*) as cnt FROM login_logs WHERE user_id=%s"
    cur.execute(total_logins_q, (target_id,))
    total_row = cur.fetchone()
    total_logins = total_row["cnt"] if total_row else 1

    risk_level = min(int((suspicious_count / max(total_logins, 1)) * 100), 100)

    # Recent login logs (last 10)
    cur.execute("""
        SELECT id as log_id, login_time as time, ip_address as ip, 
               COALESCE(location, 'Unknown') as loc,
               COALESCE(device, 'Unknown') as dev, 
               status
        FROM login_logs
        WHERE user_id=%s
        ORDER BY id DESC
        LIMIT 10
    """, (target_id,))
    recent = cur.fetchall()

    # Convert datetime objects to human-readable strings
    import datetime
    for r in recent:
        if r["time"]:
            t = r["time"]
            if isinstance(t, (datetime.datetime, datetime.date)):
                r["time"] = t.strftime("%d %b %Y, %I:%M %p")
            else:
                r["time"] = str(t)

    cur.execute("""
        SELECT trust_score, is_fake FROM fake_profile_analysis
        WHERE user_id=%s
        ORDER BY created_at DESC LIMIT 1
    """, (target_id,))
    profile_row = cur.fetchone()
    profile_trust_score = profile_row["trust_score"] if profile_row else 100
    is_fake = profile_row["is_fake"] if profile_row else False

    cur.close()
    db.close()

    return jsonify({
        "trustedDevices": trusted_devices,
        "suspiciousCount": suspicious_count,
        "newLocations": new_locations,
        "riskLevel": risk_level,
        "profileTrustScore": profile_trust_score,
        "isFake": is_fake,
        "recent": recent
    })


# ================= ACTIVITY LOGS =================
@dashboard_bp.route("/activity-logs", methods=["GET"])
@token_required()
def activity_logs(current_user_id, current_role):
    db = get_db()
    cur = db.cursor(dictionary=True)

    # Check role
    cur.execute("SELECT role FROM users WHERE id=%s", (current_user_id,))
    u_row = cur.fetchone()
    role = u_row["role"] if u_row else "user"

    if role == "admin":
        # Admin sees all logs
        cur.execute("""
            SELECT l.id as log_id, l.login_time as time, l.ip_address as ip,
                   COALESCE(l.location, 'Unknown') as loc,
                   COALESCE(l.device, 'Unknown') as dev,
                   l.status,
                   u.email as user_email
            FROM login_logs l
            JOIN users u ON l.user_id = u.id
            ORDER BY l.id DESC
            LIMIT 100
        """)
    else:
        # Regular user sees only their own
        cur.execute("""
            SELECT l.id as log_id, l.login_time as time, l.ip_address as ip,
                   COALESCE(l.location, 'Unknown') as loc,
                   COALESCE(l.device, 'Unknown') as dev,
                   l.status,
                   u.email as user_email
            FROM login_logs l
            JOIN users u ON l.user_id = u.id
            WHERE l.user_id = %s
            ORDER BY l.id DESC
            LIMIT 100
        """, (current_user_id,))

    logs = cur.fetchall()

    for l in logs:
        if l["time"]:
            l["time"] = str(l["time"])

    cur.close()
    db.close()
    return jsonify(logs)

# ================= DELETE LOG =================
@dashboard_bp.route("/delete-log", methods=["POST"])
@token_required()
def delete_log(current_user_id, role):
    data = request.get_json()
    log_id = data.get("log_id")
    
    if not log_id:
        return jsonify({"message": "log_id is required"}), 400
        
    db = get_db()
    cur = db.cursor()
    
    # Security: user can delete their own logs, admin can delete any
    if role == "admin":
        cur.execute("DELETE FROM login_logs WHERE id=%s", (log_id,))
    else:
        cur.execute("DELETE FROM login_logs WHERE id=%s AND user_id=%s", (log_id, current_user_id))
        
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "Log entry deleted successfully"}), 200

# Note: Admin routes (threats, updates, etc.) have been moved to admin_routes.py for better security (JWT) 
# and to avoid duplication. Only user-facing dashboard routes should remain here.
@dashboard_bp.route("/clear-all-logs", methods=["POST"])
@token_required()
def clear_all_logs(current_user_id, role):
    db = get_db()
    cur = db.cursor()
    if role == "admin":
        cur.execute("DELETE FROM login_logs")
    else:
        cur.execute("DELETE FROM login_logs WHERE user_id=%s", (current_user_id,))
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "Logs cleared successfully"}), 200
