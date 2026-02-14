# backend/routes/register_routes.py

from flask import Blueprint, request, jsonify
from database import get_db
from security.password_hashing import hash_password

register_bp = Blueprint("register", __name__)


from ai_ml.fake_profile_detection import analyze_profile_trustLevel

@register_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")
    
    # Module 8 features
    followers = data.get("followers", 0)
    following = data.get("following", 0)
    posts = data.get("posts", 0)
    account_age = 0 # New account

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)

    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    existing = cur.fetchone()

    if existing:
        cur.close()
        db.close()
        return jsonify({"message": "Email already registered"}), 409

    hashed_pw = hash_password(password)
    cur.execute("""
        INSERT INTO users (email, password, role)
        VALUES (%s, %s, %s)
    """, (email, hashed_pw, role))
    
    new_user_id = cur.lastrowid
    
    # Module 8 Analysis
    analysis = analyze_profile_trustLevel(followers, following, posts, account_age)
    cur.execute("""
        INSERT INTO fake_profile_analysis 
        (user_id, followers_count, following_count, post_count, account_age_days, trust_score, is_fake)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (new_user_id, followers, following, posts, account_age, analysis["trust_score"], analysis["is_fake"]))

    db.commit()
    cur.close()
    db.close()

    return jsonify({
        "message": "Registration successful!",
        "trust_score": analysis["trust_score"],
        "is_fake": analysis["is_fake"]
    }), 201
