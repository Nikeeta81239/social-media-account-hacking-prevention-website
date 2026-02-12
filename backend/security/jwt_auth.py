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
                if role and data["role"] != role:
                    return jsonify({"message": "Access denied"}), 403

                return f(data["user_id"], *args, **kwargs)

            except:
                return jsonify({"message": "Invalid token"}), 401

        return wrapper
    return decorator