# backend/routes/dashboard_routes.py

from flask import Blueprint, jsonify, request
from database import get_db

dashboard_bp = Blueprint("dashboard", __name__)


# ================= USER DASHBOARD DATA =================
@dashboard_bp.route("/dashboard-data", methods=["GET"])
def dashboard_data():
    user_id = request.args.get("user_id")

    db = get_db()
    cur = db.cursor(dictionary=True)

    # Trusted devices count (distinct devices with 'success' status)
    cur.execute("""
        SELECT COUNT(DISTINCT device) as cnt FROM login_logs
        WHERE user_id=%s AND status='success'
    """, (user_id,))
    row = cur.fetchone()
    trusted_devices = row["cnt"] if row else 0

    # Suspicious login count
    cur.execute("""
        SELECT COUNT(*) as cnt FROM login_logs
        WHERE user_id=%s AND status='Suspicious'
    """, (user_id,))
    row = cur.fetchone()
    suspicious_count = row["cnt"] if row else 0

    # New locations count (distinct locations)
    cur.execute("""
        SELECT COUNT(DISTINCT location) as cnt FROM login_logs
        WHERE user_id=%s
    """, (user_id,))
    row = cur.fetchone()
    new_locations = row["cnt"] if row else 0

    # Risk level calculation
    total_logins_q = "SELECT COUNT(*) as cnt FROM login_logs WHERE user_id=%s"
    cur.execute(total_logins_q, (user_id,))
    total_row = cur.fetchone()
    total_logins = total_row["cnt"] if total_row else 1

    risk_level = min(int((suspicious_count / max(total_logins, 1)) * 100), 100)

    # Recent login logs (last 10)
    cur.execute("""
        SELECT login_time as time, ip_address as ip, 
               COALESCE(location, 'Unknown') as loc,
               COALESCE(device, 'Unknown') as dev, 
               status
        FROM login_logs
        WHERE user_id=%s
        ORDER BY id DESC
        LIMIT 10
    """, (user_id,))
    recent = cur.fetchall()

    # Convert datetime objects to strings
    for r in recent:
        if r["time"]:
            r["time"] = str(r["time"])

    cur.execute("""
        SELECT trust_score, is_fake FROM fake_profile_analysis
        WHERE user_id=%s
        ORDER BY created_at DESC LIMIT 1
    """, (user_id,))
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
def activity_logs():
    db = get_db()
    cur = db.cursor(dictionary=True)

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
    logs = cur.fetchall()

    for l in logs:
        if l["time"]:
            l["time"] = str(l["time"])

    cur.close()
    db.close()
    return jsonify(logs)


# ================= ADMIN THREATS =================
@dashboard_bp.route("/admin-threats", methods=["GET"])
def admin_threats():
    db = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("""
        SELECT a.id as threat_id, u.email as user, a.ip_address as ip,
               a.risk_score as risk, a.status as reason
        FROM attack_logs a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 50
    """)
    threats = cur.fetchall()

    cur.close()
    db.close()
    return jsonify(threats)


# ================= ADMIN UPDATE USER (BLOCK/ALLOW) =================
@dashboard_bp.route("/admin-update-user", methods=["POST"])
def admin_update_user():
    data = request.get_json()
    user_email = data.get("user")
    action = data.get("action")

    db = get_db()
    cur = db.cursor(dictionary=True)

    # Get user id from email
    cur.execute("SELECT id FROM users WHERE email=%s", (user_email,))
    user = cur.fetchone()

    if not user:
        cur.close()
        db.close()
        return jsonify({"message": "User not found"}), 404

    user_id = user["id"]

    if action == "block":
        # Check if already blocked
        cur.execute("SELECT id FROM blocked_users WHERE user_id=%s", (user_id,))
        already = cur.fetchone()
        if not already:
            cur.execute("""
                INSERT INTO blocked_users (user_id, reason)
                VALUES (%s, %s)
            """, (user_id, "Blocked by admin"))
            db.commit()
        cur.close()
        db.close()
        return jsonify({"message": f"{user_email} has been blocked"})

    elif action == "allow":
        # Remove from blocked list
        cur.execute("DELETE FROM blocked_users WHERE user_id=%s", (user_id,))
        db.commit()
        cur.close()
        db.close()
        return jsonify({"message": f"{user_email} has been allowed"})

    cur.close()
    db.close()
    return jsonify({"message": "Invalid action"}), 400


# ================= BLOCKED USERS LIST =================
@dashboard_bp.route("/blocked-users", methods=["GET"])
def blocked_users():
    db = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("""
        SELECT u.email as user, 
               COALESCE(
                   (SELECT ip_address FROM login_logs WHERE user_id=u.id ORDER BY id DESC LIMIT 1),
                   'N/A'
               ) as ip,
               CASE 
                   WHEN b.reason LIKE '%AI%' THEN 'AI'
                   ELSE 'Admin'
               END as 'by',
               b.reason
        FROM blocked_users b
        JOIN users u ON b.user_id = u.id
        ORDER BY b.blocked_time DESC
    """)
    blocked = cur.fetchall()

    cur.close()
    db.close()
    return jsonify(blocked)


# ================= UNBLOCK USER =================
@dashboard_bp.route("/unblock-user", methods=["POST"])
def unblock_user():
    data = request.get_json()
    user_email = data.get("user")

    db = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT id FROM users WHERE email=%s", (user_email,))
    user = cur.fetchone()

    if not user:
        cur.close()
        db.close()
        return jsonify({"message": "User not found"}), 404

    cur.execute("DELETE FROM blocked_users WHERE user_id=%s", (user["id"],))
    db.commit()

    cur.close()
    db.close()

    return jsonify({"message": f"{user_email} has been unblocked"})


# ================= DELETE ACTIVITY LOG =================
@dashboard_bp.route("/delete-log", methods=["POST"])
def delete_log():
    data = request.get_json()
    log_id = data.get("log_id")
    
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM login_logs WHERE id=%s", (log_id,))
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "Log entry deleted successfully"}), 200


# ================= DELETE THREAT LOG =================
@dashboard_bp.route("/delete-threat", methods=["POST"])
def delete_threat():
    data = request.get_json()
    threat_id = data.get("threat_id")
    
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM attack_logs WHERE id=%s", (threat_id,))
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "Threat record cleared successfully"}), 200
