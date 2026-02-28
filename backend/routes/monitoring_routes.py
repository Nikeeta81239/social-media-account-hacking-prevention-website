import datetime
from flask import Blueprint, jsonify, request
from database import get_db
from security.jwt_auth import token_required

monitoring_bp = Blueprint("monitoring", __name__)

@monitoring_bp.route("/xai/latest", methods=["GET"])
@token_required()
def get_latest_xai(current_user_id, role):
    # If admin and target user_id provided, use it. Otherwise use current_user_id.
    target_id = request.args.get("user_id")
    if role == "admin" and target_id:
        user_id = target_id
    else:
        user_id = current_user_id

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT x.*, u.email FROM xai_explanations x
        JOIN users u ON x.user_id = u.id
        WHERE x.user_id=%s
        ORDER BY x.created_at DESC
        LIMIT 1
    """, (user_id,))

    data = cursor.fetchone()
    conn.close()

    if not data:
        return jsonify({"message": "No suspicious activity"}), 200

    # Serialize datetime fields for JSON
    for key, val in data.items():
        if isinstance(val, (datetime.datetime, datetime.date)):
            data[key] = val.strftime("%Y-%m-%d %H:%M:%S")

    return jsonify(data)
