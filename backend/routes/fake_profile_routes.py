from flask import Blueprint, request, jsonify
from database import get_db
from ai_ml.fake_profile_detection import analyze_profile_trustLevel
from security.jwt_auth import token_required

fake_profile_bp = Blueprint("fake_profile", __name__)

@fake_profile_bp.route("/analyze-profile", methods=["POST"])
@token_required()
def analyze_user_profile(current_user_id, role):
    data = request.get_json()
    user_id = current_user_id

    followers = data.get("followers", 0)
    following = data.get("following", 0)
    posts = data.get("posts", 0)
    account_age = data.get("account_age", 0)

    # Module 8: Analyze trust
    result = analyze_profile_trustLevel(followers, following, posts, account_age)

    db = get_db()
    cur = db.cursor()
    
    cur.execute("""
        INSERT INTO fake_profile_analysis 
        (user_id, followers_count, following_count, post_count, account_age_days, trust_score, is_fake)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (user_id, followers, following, posts, account_age, result["trust_score"], result["is_fake"]))
    
    db.commit()
    cur.close()
    db.close()

    return jsonify({
        "status": "success",
        "analysis": result
    }), 200

@fake_profile_bp.route("/profile-stats", methods=["GET"])
@token_required()
def get_profile_stats(current_user_id, role):
    user_id = current_user_id
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    cur.execute("""
        SELECT * FROM fake_profile_analysis 
        WHERE user_id=%s 
        ORDER BY created_at DESC LIMIT 1
    """, (user_id,))
    
    data = cur.fetchone()
    cur.close()
    db.close()
    
    if not data:
        return jsonify({"message": "No analysis found"}), 404
        
    return jsonify(data), 200
