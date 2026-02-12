def predict_risk(features):
    score = (
        features["device_change"] * 0.4 +
        features["location_change"] * 0.4 +
        (1 if features["login_hour"] < 5 else 0) * 0.2
    )

    if score < 0.3:
        return {"level": "LOW", "action": "ALLOW"}
    elif score < 0.6:
        return {"level": "MEDIUM", "action": "OTP"}
    else:
        return {"level": "HIGH", "action": "BLOCK"}
