def analyze_profile_trustLevel(followers, following, posts, account_age):
    # Module 8: Fake Profile Detection Logic
    
    # 1. Followers/Following ratio
    ratio = followers / max(following, 1)
    
    # 2. Activity consistency (simulation)
    # 3. Account age factor
    
    score = 100
    reasons = []
    
    if ratio < 0.1:
        score -= 30
        reasons.append("Very low followers-to-following ratio")
    
    if posts < 5:
        score -= 20
        reasons.append("Low post count")
        
    if account_age < 30:
        score -= 20
        reasons.append("Very new account")
        
    is_fake = score < 50
    
    return {
        "trust_score": max(score, 0),
        "is_fake": is_fake,
        "reasons": reasons
    }
