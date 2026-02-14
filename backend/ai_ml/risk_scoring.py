def predict_risk(features):
    # Enhanced weighted scoring logic (Simulation of ML model)
    score = (
        features["device_change"] * 0.35 +
        features["location_change"] * 0.35 +
        features["ip_change"] * 0.20 +
        (0.1 if features["login_hour"] < 6 or features["login_hour"] > 23 else 0)
    )

    risk_percent = int(score * 100)

    # If no previous history or any change detected, request OTP for safety
    if score == 0 and features.get("history_count", 0) > 0:
        return {"level": "LOW", "action": "ALLOW", "score": risk_percent}
    elif score < 0.65:
        return {"level": "MEDIUM", "action": "OTP", "score": risk_percent}
    else:
        return {"level": "HIGH", "action": "BLOCK", "score": risk_percent}
