# backend/security/jwt_auth.py

import jwt
from functools import wraps
from flask import request, jsonify
from config import Config

def generate_jwt(user_id, role, is_restricted=False):
    payload = {
        "user_id": user_id,
        "role": role,
        "is_restricted": is_restricted
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
                is_restricted = data.get("is_restricted", False)
                
                # Check restriction: Restricted users can only access XAI related APIs
                if is_restricted:
                    # Allowed internal API paths for restricted users
                    allowed_paths = [
                        "/api/xai/latest", 
                        "/api/admin/user-behavior",
                        "/api/deviation-data" # Some restricted users might see deviation
                    ]
                    # Simple check for path
                    is_allowed = False
                    for p in allowed_paths:
                        if request.path.startswith(p):
                            is_allowed = True
                            break
                    
                    if not is_allowed:
                        return jsonify({
                            "message": "Security Restriction: Your account access is limited to the Explainable AI (XAI) security brief.",
                            "is_restricted": True
                        }), 403

                # REQUIRMENT: Check if user is currently blocked in DB
                # Bypassed for ADMIN to ensure full access authority
                if data.get("role") != 'admin':
                    from database import get_db
                    import datetime
                    db = get_db()
                    cur = db.cursor(dictionary=True)
                    cur.execute("SELECT * FROM blocked_users WHERE user_id=%s ORDER BY blocked_time DESC LIMIT 1", (user_id,))
                    block = cur.fetchone()
                    
                    if block:
                        # Use UTC for consistency if database stores UTC
                        block_time = block['blocked_time']
                        diff = (datetime.datetime.utcnow() - block_time).total_seconds()
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
                import traceback
                print(f"JWT ERROR: {e}")
                traceback.print_exc()
                return jsonify({"message": f"Invalid token or system error: {str(e)}"}), 401

        return wrapper
    return decorator
