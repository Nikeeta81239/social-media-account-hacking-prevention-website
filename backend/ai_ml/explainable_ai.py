import datetime
import google.generativeai as genai
from config import Config
from ai_ml.risk_scoring import get_model

# ─────────────────────────────────────────────────────────────────────────────
# 🟢 GEMINI AI CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
try:
    genai.configure(api_key=Config.GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
except Exception as e:
    print(f"[XAI ERROR] Gemini Setup Failed: {e}")
    gemini_model = None

def get_gemini_security_brief(risk_score, narrative_details):
    """🟢 Generates a human-like explanation using Google Gemini."""
    if not gemini_model:
        return None
        
    prompt = f"""
    You are an AI Security Assistant for a Social Media Protection platform called 'AI Cyber Shield'. 
    Explain this login event to the user.
    Risk Score: {risk_score}%
    Detected Anomalies/Trends: {narrative_details}
    
    Guidelines:
    - If Risk < 31%: Be welcoming and confirm your pattern matches perfectly. Use 'Behavioral Consistency'.
    - If Risk 31-69%: Explain that identity verification (OTP) is required as a standard security precaution due to a slight pattern shift.
    - If Risk >= 70%: Explain clearly that access is restricted for 30 seconds for protection because this login looks suspicious or unrecognized.
    - Limit to 2 sentences. Be professional and supportive.
    """
    try:
        response = gemini_model.generate_content(prompt)
        # Clean up output (sometimes Gemini uses markdown, we want plain text)
        return response.text.strip().replace("*", "").replace("#", "")
    except Exception as e:
        print(f"[GEMINI API ERROR] {e}")
        return None

# ─────────────────────────────────────────────────────────────────────────────
# CORE XAI LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def _behavioral_reason_for_feature(feature_name, value, threshold_high=0.6, threshold_mid=0.3):
    if feature_name == "time_deviation":
        if value > threshold_high: return "Your current login significantly deviates from your usage profile.", True
        elif value > threshold_mid: return "A shift in your login timing was detected.", False
        else: return "Your login timing matches your normal schedule.", False
    elif feature_name == "location_deviation":
        if value >= 1.0: return "Your current location is not recognized from your history.", True
        elif value > threshold_mid: return "A partial location change was detected.", False
        else: return "You are accessing from a familiar location.", False
    elif feature_name == "device_deviation":
        if value >= 1.0: return "This device has not been used before to access your account.", True
        elif value > threshold_mid: return "A slight difference in device fingerprint was detected.", False
        else: return "Your device matches a previously trusted device.", False
    elif feature_name == "frequency_deviation":
        if value > threshold_high: return "Unusually high number of login attempts detected.", True
        elif value > threshold_mid: return "Login frequency is slightly higher than normal.", False
        else: return "Your login frequency is within normal range.", False
    return "Behavioral pattern is normal.", False


def generate_xai_explanation(risk_score, features):
    feature_names = ['time_deviation', 'location_deviation', 'device_deviation', 'frequency_deviation']
    values = [features.get(f, 0.0) for f in feature_names]
    weights = {'time_deviation': 0.20, 'location_deviation': 0.40, 'device_deviation': 0.30, 'frequency_deviation': 0.10}

    contributions = []
    for i, name in enumerate(feature_names):
        val = values[i]
        impact = val * weights[name]
        contributions.append({
            "feature": name, "value": val, "impact": round(impact, 4), 
            "weight": weights[name], "direction": "Increased Risk" if val > 0.3 else "Stable"
        })

    contributions.sort(key=lambda x: x["impact"], reverse=True)

    # ── Preparation for Gemini ──
    lime_details = []
    for c in contributions:
        if c["impact"] > 0.05:
            feat_name = c["feature"].replace("_", " ").replace("deviation", "").strip().title()
            lime_details.append(f"unusual {feat_name}")
    narrative_summary = ", ".join(lime_details) if lime_details else "Consistent behavior"

    # 🟢 Call Gemini
    gemini_reason = get_gemini_security_brief(risk_score, narrative_summary)

    # ── Metadata ──
    current_feats = features.get("current_features", {})
    login_time_utc = current_feats.get("login_time_utc", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    login_location = current_feats.get("location", "Unknown Location")
    login_device = current_feats.get("device", "Unknown Device")
    failed_ever = features.get("total_failed_ever", 0)
    freq_24h = features.get("frequency_counts", {}).get("24h", 0)
    history_count = features.get("history_count", 0)

    # ── Risk Level classification ──
    if risk_score >= 70:
        risk_level_name, suggested_action = "High Risk", "⛔ Identity Verification Required. Access restricted for 30s."
    elif risk_score >= 31:
        risk_level_name, suggested_action = "Medium Risk", "⚠ Identity verification required via OTP."
    else:
        risk_level_name, suggested_action = "Low Risk", "✅ Access permitted normally."

    # ── Final Outcome ──
    default_reason = f"Our AI detected a {risk_level_name.lower()} login. {suggested_action}"
    reason = gemini_reason if gemini_reason else default_reason
    
    # ── Formatting for Frontend ──
    lime_user_prompt = f"✨ REAL-TIME AI ANALYSIS: {reason}" if gemini_reason else reason

    return {
        "decision": risk_level_name,
        "risk_score": risk_score,
        "reason": reason,
        "lime_user_prompt": lime_user_prompt,
        "suggested_action": suggested_action,
        "trust_score": max(int(100 - risk_score), 5),
        "login_time_utc": login_time_utc,
        "login_location": login_location,
        "login_device": login_device,
        "failed_ever": failed_ever,
        "freq_24h": freq_24h,
        "history_count": history_count,
        "contributions": contributions,
        "feature_weights": weights,
        "what_if": "If you used your usual device at your normal time, access would be low-risk.",
        "dynamic_analysis": [f"{c['feature'].replace('_',' ').title()}: +{int(c['impact']*100)}%" for c in contributions],
        "lime_plain_reasons": [{"reason": _behavioral_reason_for_feature(c["feature"], c["value"])[0]} for c in contributions[:3]]
    }
