def generate_xai_explanation(risk_score, features):
    ranked = sorted(features.items(), key=lambda x: x[1], reverse=True)

    top_reasons = []
    if features.get("login_time", 0) > 0.3:
        top_reasons.append("Login at unusual time")
    if features.get("ip_change", 0) > 0.2:
        top_reasons.append("Login from new IP address")
    if features.get("device_mismatch", 0) > 0.2:
        top_reasons.append("Unrecognized device detected")

    top_reasons = top_reasons[:3]

    what_if = "If login occurred from a trusted device and location, access would be allowed."

    trust_score = int(sum([features[f] for f in features]) * 100)

    return {
        "decision": "Suspicious" if risk_score > 70 else "Genuine",
        "risk": risk_score,
        "top_reasons": top_reasons,
        "what_if": what_if,
        "trust_score": trust_score
    }
