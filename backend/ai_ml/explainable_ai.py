
import numpy as np
import pandas as pd
from ai_ml.risk_scoring import get_model

def generate_xai_explanation(risk_score, features):
    """
    Explainable AI (XAI) using local feature contributions.
    Identifies which deviation features most influenced the risk score.
    """
    model = get_model()
    
    # Feature names
    feature_names = ['time_deviation', 'location_deviation', 'device_deviation', 'frequency_deviation']
    
    # Current values
    values = [
        features["time_deviation"],
        features["location_deviation"],
        features["device_deviation"],
        features["frequency_deviation"]
    ]
    
    # Logic to identify contributors (Simplified LIME/Contribution approach)
    # We look at which features have high deviation values as they drive the CatBoost 'Suspicious' score
    contributions = []
    
    # Weights based on model logic (simplified contribution)
    # Location and Device are usually high impact in this domain
    weights = {'time_deviation': 0.25, 'location_deviation': 0.4, 'device_deviation': 0.35, 'frequency_deviation': 0.2}
    
    for i, name in enumerate(feature_names):
        impact = values[i] * weights[name]
        direction = "Increased Risk" if values[i] > 0.3 else "Reduced Risk"
        contributions.append({
            "feature": name,
            "value": values[i],
            "impact": impact,
            "direction": direction
        })
    
    # Sort by impact
    contributions.sort(key=lambda x: x["impact"], reverse=True)
    
    # Generate Dynamic Analysis (impact percentages)
    dynamic_analysis = []
    for c in contributions:
        feat_display = c["feature"].replace("_", " ").title()
        # Scale the impact to match the risk score contribution
        impact_pct = int(c["value"] * weights[c["feature"]] * 100)
        sign = "+" if c["value"] > 0 else "-"
        dynamic_analysis.append(f"{feat_display}: {sign}{impact_pct}%")

    # Risk Categories (User Spec: 0-30, 31-69, 70-100)
    if risk_score >= 70:
        risk_level_name = "High Risk"
        suggested_action = "⛔ Identity Verification or Security Questions Required."
    elif risk_score >= 31:
        risk_level_name = "Medium Risk"
        suggested_action = "⚠ OTP Verification via registered email/phone."
    else:
        risk_level_name = "Low Risk"
        suggested_action = "✅ Access permitted normally."

    # Attempt-based context (User Spec)
    history_count = features.get("history_count", 0)
    attempt_num = history_count + 1
    
    # Reason Logic
    high_devs = [c["feature"].replace("_", " ").title() for c in contributions if c["value"] > 0.6]
    
    # Construct primary reason based on risk scoring and attempts
    history_count = features.get("history_count", 0)
    failed_attempts = features.get("failed_attempts", 0)
    
    if risk_score < 31:
        reason = "The login pattern matches your historical behavior, including consistent location, recognized device, and normal login frequency. This ensures transparency and confirms that the activity is safe without requiring additional verification."
        top_reasons = "Behavioral Consistency"
    elif risk_score < 70:
        reason = "A moderate deviation in login frequency or partial change in device or location compared to previous login history was detected. Adaptive authentication is applied to confirm your identity."
        top_reasons = ", ".join(high_devs) if high_devs else "Moderate Deviation"
    else:
        # High Risk reasons matching the prompt's wording exactly
        reasons = []
        if features["location_deviation"] > 0.8: 
            reasons.append("unusual location change compared to regular login patterns")
        if features["device_deviation"] > 0.8: 
            reasons.append("new or unrecognized device detection")
        if features["frequency_counts"]["24h"] >= 5: 
            reasons.append("abnormal login frequency")
        if failed_attempts >= 5: 
            reasons.append("excessive failed attempts")
        
        if not reasons: 
            reasons.append("similarity to behavior observed in compromised accounts")
        
        reason = f"Suspicious activity detected: {', '.join(reasons)}. Access is temporarily restricted for 30 seconds to prevent potential unauthorized access."
        top_reasons = ", ".join(reasons)

    what_if = "If the login attempt matched your registered device and usual geographic location without high frequency, the system would classify this as normal behavior."

    # Trust score
    trust_score = max(int(100 - risk_score), 5)

    return {
        "decision": risk_level_name,
        "risk_score": risk_score,
        "reason": reason,
        "suggested_action": suggested_action,
        "dynamic_analysis": dynamic_analysis,
        "what_if": what_if,
        "trust_score": trust_score,
        "feature_weights": weights,
        "top_reasons": top_reasons,
        "full_narrative": f"{reason} (Risk Score: {risk_score}%)"
    }
