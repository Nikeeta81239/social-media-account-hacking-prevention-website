from flask import Blueprint, jsonify
from database import get_db
from security.jwt_auth import token_required

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/admin/dashboard")
@token_required(role="admin")
def admin_dashboard_stats(user_id, role):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE risk IN ('medium', 'high')")
    threats = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM blocked_users")
    blocked = cur.fetchone()[0]
    cur.close()
    db.close()
    return jsonify({"users": users, "threats": threats, "blocked": blocked})

@admin_bp.route("/admin/blocked-users")
@token_required(role="admin")
def list_blocked_users(user_id, role):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT b.id, u.email, u.id as user_id, b.reason, b.blocked_time as blocked_at,
               IFNULL((SELECT risk_score FROM xai_explanations WHERE user_id=u.id ORDER BY created_at DESC LIMIT 1), 0) as risk
        FROM blocked_users b
        JOIN users u ON b.user_id = u.id
        ORDER BY b.blocked_time DESC
    """)
    blocked = cur.fetchall()
    cur.close()
    db.close()
    return jsonify(blocked)

@admin_bp.route("/admin/unblock-user", methods=["POST"])
@token_required(role="admin")
def admin_unblock_user(user_id, role):
    import flask
    data = flask.request.get_json()
    target_user_id = data.get("user_id")
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM blocked_users WHERE user_id=%s", (target_user_id,))
    cur.execute("UPDATE users SET failed_attempts=0 WHERE id=%s", (target_user_id,))
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "User unblocked successfully"})

@admin_bp.route("/admin-threats")
@token_required(role="admin")
def get_admin_threats(user_id, role):
    db = get_db()
    cur = db.cursor(dictionary=True)
    # Correctly joining with the latest IP address, location, and device for each user
    cur.execute("""
        SELECT x.id as threat_id, u.id as user_id, u.email as user, l.ip_address as ip, 
               l.location as location, l.device as device,
               x.risk_score as risk, x.decision as risk_level, x.top_reasons as reason
        FROM xai_explanations x
        JOIN users u ON x.user_id = u.id
        LEFT JOIN (
            SELECT t1.user_id, t1.ip_address, t1.location, t1.device
            FROM login_logs t1
            INNER JOIN (
                SELECT user_id, MAX(login_time) as max_time
                FROM login_logs
                GROUP BY user_id
            ) t2 ON t1.user_id = t2.user_id AND t1.login_time = t2.max_time
        ) l ON l.user_id = u.id
        WHERE x.risk_score >= 40
        ORDER BY x.created_at DESC LIMIT 50
    """)
    threats = cur.fetchall()
    cur.close()
    db.close()
    return jsonify(threats)

@admin_bp.route("/admin-update-user", methods=["POST"])
@token_required(role="admin")
def admin_update_user(user_id, role):
    import flask
    data = flask.request.get_json()
    email = data.get("user")
    action = data.get("action")
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    if action == "block":
        reason = data.get("reason") or "Admin manual block"
        cur.execute("INSERT INTO blocked_users (user_id, reason) VALUES (%s, %s)", (user['id'], reason))
    elif action == "allow":
        cur.execute("DELETE FROM blocked_users WHERE user_id=%s", (user['id'],))
        cur.execute("UPDATE users SET failed_attempts=0 WHERE id=%s", (user['id'],))
    
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": f"User {action}ed successfully"})

@admin_bp.route("/delete-threat", methods=["POST"])
@token_required(role="admin")
def delete_threat(user_id, role):
    import flask
    data = flask.request.get_json()
    threat_id = data.get("threat_id")
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM xai_explanations WHERE id=%s", (threat_id,))
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "Threat record cleared successfully"})
@admin_bp.route("/clear-all-threats", methods=["POST"])
@token_required(role="admin")
def clear_all_threats(user_id, role):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM xai_explanations WHERE risk_score >= 40")
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "All threat records cleared successfully"}), 200

@admin_bp.route("/clear-all-blocked", methods=["POST"])
@token_required(role="admin")
def clear_all_blocked(user_id, role):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM blocked_users")
    cur.execute("UPDATE users SET failed_attempts=0")
    db.commit()
    cur.close()
    db.close()
    return jsonify({"message": "All accounts unblocked successfully"}), 200

@admin_bp.route("/admin/users")
@token_required(role="admin")
def list_all_users(user_id, role):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, email FROM users WHERE role='user'")
    users = cur.fetchall()
    cur.close()
    db.close()
    return jsonify(users)
