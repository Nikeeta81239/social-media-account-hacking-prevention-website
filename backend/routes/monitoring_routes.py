from flask import Blueprint, jsonify, request
from database import get_db
from ai_ml.explainable_ai import generate_xai_explanation

monitoring_bp = Blueprint("monitoring", __name__)

@monitoring_bp.route("/xai/latest", methods=["GET"])
def get_latest_xai():
    user_id = request.args.get("user_id")

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM xai_explanations
        WHERE user_id=%s
        ORDER BY created_at DESC
        LIMIT 1
    """, (user_id,))
    
    data = cursor.fetchone()
    conn.close()

    if not data:
        return jsonify({"message": "No suspicious activity"}), 200

    return jsonify(data)
