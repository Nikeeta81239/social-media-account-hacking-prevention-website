from flask import Blueprint, jsonify
from database import get_db
from security.jwt_auth import token_required

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/api/admin/dashboard")
@token_required(role="admin")  # only accessible to admins
def admin_dashboard(user_id):
    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM login_logs WHERE status='Suspicious'")
    threats = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM blocked_users")
    blocked = cur.fetchone()[0]

    return jsonify({
        "users": users,
        "threats": threats,
        "blocked": blocked
    })
