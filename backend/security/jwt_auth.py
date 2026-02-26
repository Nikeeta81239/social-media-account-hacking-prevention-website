# backend/security/jwt_auth.py

import jwt
from functools import wraps
from flask import request, jsonify
from config import Config

def generate_jwt(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role
    }
    token = jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")
    return token

def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")

            if not token:
                return jsonify({"message": "Token missing"}), 401

            try:
                data = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
                user_id = data["user_id"]
                
                # REQUIRMENT: Check if user is currently blocked in DB
                from database import get_db
                import datetime
                db = get_db()
                cur = db.cursor(dictionary=True)
                cur.execute("SELECT * FROM blocked_users WHERE user_id=%s ORDER BY blocked_time DESC LIMIT 1", (user_id,))
                block = cur.fetchone()
                
                if block:
                    diff = (datetime.datetime.now() - block['blocked_time']).total_seconds()
                    if diff < 30:
                        cur.close()
                        db.close()
                        return jsonify({
                            "status": "blocked",
                            "message": f"Access Restricted: {block['reason']}",
                            "time_left": 30 - int(diff),
                            "reason": block['reason']
                        }), 403
                
                cur.close()
                db.close()

                if role and data["role"] != role:
                    return jsonify({"message": "Access denied"}), 403

                # PASS BOTH user_id and role to the function
                return f(user_id, data["role"], *args, **kwargs)

            except Exception as e:
                return jsonify({"message": f"Invalid token or system error: {str(e)}"}), 401

        return wrapper
    return decorator