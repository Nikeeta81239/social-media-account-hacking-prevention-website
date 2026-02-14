def generate_xai_explanation(risk_score, features):
    reasons = []
    if features.get("device_change") == 1:
        reasons.append("Unrecognized device detected")
    if features.get("location_change") == 1:
        reasons.append("Login from an unusual location")
    if features.get("ip_change") == 1:
        reasons.append("Login from a new IP address")
    if features.get("login_hour", 0) < 6 or features.get("login_hour", 0) > 23:
        reasons.append("Login attempt at an unusual hour")

    # Rank top 3 reasons
    top_reasons = reasons[:3]
    
    what_if = "If this login were from a recognized device and within normal hours, the risk score would be below 20%."
    
    # Trust score based on how many features matched history
    trust_elements = 4 - (features.get("device_change") + features.get("location_change") + features.get("ip_change"))
    trust_score = max(int((trust_elements / 4) * 100), 20)

    return {
        "decision": "Suspicious" if risk_score > 60 else "Genuine",
        "risk_score": risk_score,
        "top_reasons": ", ".join(top_reasons) if top_reasons else "None (Normal Behavior)",
        "what_if": what_if,
        "trust_score": trust_score
    }
