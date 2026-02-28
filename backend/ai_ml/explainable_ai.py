
import datetime
from ai_ml.risk_scoring import get_model

# ─────────────────────────────────────────────────────────────────────────────
# PLAIN-LANGUAGE TEMPLATES for LIME results
# These translate raw feature deviations into user-friendly behavioral reasons.
# Admin panel still sees raw scores separately.
# ─────────────────────────────────────────────────────────────────────────────

def _behavioral_reason_for_feature(feature_name, value, threshold_high=0.6, threshold_mid=0.3):
    """
    Convert a raw LIME feature deviation into a plain-language behavioral reason.
    Returns (plain_text, is_suspicious)
    """
    if feature_name == "time_deviation":
        if value > threshold_high:
            return "Your current login significantly deviates from your established night behavior/usage profile.", True
        elif value > threshold_mid:
            return "A shift in your nocturnal login pattern was detected.", False
        else:
            return "Your login timing perfectly matches your normal night/day behavioral schedule.", False

    elif feature_name == "location_deviation":
        if value >= 1.0:
            return "Your current location is not recognized from your previous login history.", True
        elif value > threshold_mid:
            return "A partial location change was detected compared to your usual access points.", False
        else:
            return "You are accessing from a familiar location.", False

    elif feature_name == "device_deviation":
        if value >= 1.0:
            return "This device has not been used before to access your account.", True
        elif value > threshold_mid:
            return "A slight difference in device fingerprint was detected.", False
        else:
            return "Your device matches a previously trusted device.", False

    elif feature_name == "frequency_deviation":
        if value > threshold_high:
            return "An unusually high number of login attempts was detected in a short period.", True
        elif value > threshold_mid:
            return "Login frequency is slightly higher than your normal pattern.", False
        else:
            return "Your login frequency is within normal range.", False

    return "Behavioral pattern is normal.", False


def generate_xai_explanation(risk_score, features):
    """
    Explainable AI (XAI) using local LIME-style feature contributions.
    
    - For normal users: plain English behavioral reasons (no raw numbers/weights).
    - For admin panel: full technical breakdown (risk score, feature weights, etc.).
    """

    # ── Feature definitions ──
    feature_names = ['time_deviation', 'location_deviation', 'device_deviation', 'frequency_deviation']

    values = [
        features.get("time_deviation", 0.0),
        features.get("location_deviation", 0.0),
        features.get("device_deviation", 0.0),
        features.get("frequency_deviation", 0.0),
    ]

    # Relative importance weights for LIME-style local explanation
    # (Location & Device are higher impact in identity security)
    weights = {
        'time_deviation':      0.20,
        'location_deviation':  0.40,
        'device_deviation':    0.30,
        'frequency_deviation': 0.10,
    }

    # ── Compute LIME-style contributions ──
    contributions = []
    for i, name in enumerate(feature_names):
        val = values[i]
        impact = val * weights[name]
        contributions.append({
            "feature":    name,
            "value":      val,
            "impact":     round(impact, 4),
            "weight":     weights[name],
            "direction":  "Increased Risk" if val > 0.3 else "Stable"
        })

    # Sort by impact descending
    contributions.sort(key=lambda x: x["impact"], reverse=True)

    # ── Plain-language LIME reasons (top 2–3 factors only) ──
    lime_plain_reasons = []
    for c in contributions[:3]:  # Only top 3
        plain_text, is_suspicious = _behavioral_reason_for_feature(c["feature"], c["value"])
        lime_plain_reasons.append({
            "reason":        plain_text,
            "is_suspicious": is_suspicious
        })

    # ── Admin-level technical dynamic analysis ──
    admin_dynamic_analysis = []
    for c in contributions:
        feat_display = c["feature"].replace("_", " ").title()
        impact_pct = int(c["value"] * weights[c["feature"]] * 100)
        sign = "+" if c["value"] > 0 else "-"
        admin_dynamic_analysis.append(f"{feat_display}: {sign}{impact_pct}%")

    # ── Current login metadata ──
    current_feats = features.get("current_features", {})
    login_time_utc = current_feats.get("login_time_utc", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    login_location = current_feats.get("location", "Unknown Location")
    login_device = current_feats.get("device", "Unknown Device")
    history_count = features.get("history_count", 0)
    failed_ever = features.get("total_failed_ever", 0)
    freq_24h = features.get("frequency_counts", {}).get("24h", 0)

    # ── Risk level classification ──
    if risk_score >= 70:
        risk_level_name = "High Risk"
        suggested_action = "⛔ Identity Verification Required. Your account access has been temporarily restricted for 30 seconds."
    elif risk_score >= 31:
        risk_level_name = "Medium Risk"
        suggested_action = "⚠ For your security, please verify your identity via OTP sent to your registered email."
    else:
        risk_level_name = "Low Risk"
        suggested_action = "✅ Access permitted normally."

    # ── Plain-language primary reason for NORMAL USERS (with LIME % impact) ──
    # Requirement: unusual time +15%, new device +25%
    lime_details = []
    for c in contributions:
        if c["impact"] > 0.05:
            feat_name = c["feature"].replace("_", " ").replace("deviation", "").strip().title()
            pct = int(c["impact"] * 100)
            lime_details.append(f"unusual {feat_name} (+{pct}%)")

    lime_detail_str = ", ".join(lime_details[:2]) if lime_details else "behavioral consistency"

    # --- SPECIFIC USER REQUESTED MESSAGES ---
    lime_msg = "This login matches your usual device, location, and activity pattern, so no suspicious behavior was detected."
    trust_msg = "Your current activity is highly trusted based on consistent past behavior."
    eli5_msg = "The system primarily checks location, device, time, and login frequency to ensure account safety."
    catboost_msg = "Our AI security model analyzed this login and determined it to be safe."
    final_decision_msg = "Access is securely permitted as the risk level is low."

    if risk_score < 31:
        # Safe login — use the simple, reassuring message (ELI5)
        reason = final_decision_msg
        lime_user_prompt = (
            f"🌍 GLOBAL FEATURE IMPORTANCE (ELI5): {eli5_msg}\n\n"
            f"LIME: {lime_msg}\n\n"
            f"Behavior Trust Score: {trust_msg}\n\n"
            f"CatBoost AI Prediction: {catboost_msg}\n\n"
            f"Final AI Decision: {final_decision_msg}"
        )
        top_reasons = "Behavioral Consistency"

    elif risk_score < 70:
        suspicious_factors = [r["reason"] for r in lime_plain_reasons if r["is_suspicious"]]
        
        if suspicious_factors:
            combined = " Additionally, ".join(suspicious_factors[:2])
            reason = (
                f"Our system detected a moderate change in your login behavior. {combined} "
                "As a security measure, we need to verify your identity before granting access."
            )
        else:
            reason = (
                "A moderate deviation in your login pattern was detected. "
                "As a precaution, identity verification is required."
            )

        lime_user_prompt = f"{reason} (Risk Factors detected: {lime_detail_str})"
        top_reasons = ", ".join(lime_details[:2]) if lime_details else "Moderate Behavioral Change"

    else:
        # High Risk — explain clearly but without raw numbers
        suspicious_factors = [r["reason"] for r in lime_plain_reasons if r["is_suspicious"]]

        risk_reasons = []
        if features.get("location_deviation", 0) >= 1.0:
            risk_reasons.append("your current location is not recognized from your login history")
        if features.get("device_deviation", 0) >= 1.0:
            risk_reasons.append("this device has never been used on your account before")
        if freq_24h >= 5:
            risk_reasons.append(f"there have been {freq_24h} login attempts in the last 24 hours, which is unusually high")
        if failed_ever >= 5:
            risk_reasons.append("multiple consecutive failed login attempts were recorded")

        if not risk_reasons:
            risk_reasons.append("your current login pattern significantly differs from your established behavior")

        reason = (
            "Our security system has flagged this login as high risk because "
            + ", and ".join(risk_reasons[:3])
            + ". Access has been temporarily restricted for 30 seconds to protect your account."
        )
        lime_user_prompt = reason
        top_reasons = ", ".join(risk_reasons[:2])

    # ── What-If scenario (user-friendly) ──
    what_if = (
        "If you had logged in from your usual device and location at your normal time, "
        "the system would have recognized this as safe access and allowed you in without any extra steps."
    )

    # ── Trust Score ──
    trust_score = max(int(100 - risk_score), 5)

    # ── Full narrative for admin / logs ──
    full_narrative = (
        f"Risk Score: {risk_score}% | Login Time (UTC): {login_time_utc} | "
        f"Location: {login_location} | Device: {login_device} | "
        f"Failed Attempts (All Time): {failed_ever} | Logins (24h): {freq_24h} | "
        f"History Records: {history_count}"
    )

    return {
        # ── User-facing (plain language) ──
        "decision":             risk_level_name,
        "risk_score":           risk_score,
        "reason":               reason,
        "lime_user_prompt":     lime_user_prompt,
        "lime_plain_reasons":   lime_plain_reasons,
        "suggested_action":     suggested_action,
        "what_if":              what_if,
        "trust_score":          trust_score,
        "login_time_utc":       login_time_utc,

        # New specific keys for the frontend
        "lime_msg":             lime_msg if risk_score < 31 else None,
        "trust_msg":            trust_msg if risk_score < 31 else None,
        "eli5_msg":             eli5_msg if risk_score < 31 else None,
        "catboost_msg":         catboost_msg if risk_score < 31 else None,
        "final_decision_msg":   final_decision_msg if risk_score < 31 else None,

        # ── Admin-facing (technical) ──
        "dynamic_analysis":     admin_dynamic_analysis,
        "feature_weights":      weights,
        "top_reasons":          top_reasons,
        "full_narrative":       full_narrative,
        "contributions":        contributions,

        # ── Metadata ──
        "login_location":       login_location,
        "login_device":         login_device,
        "history_count":        history_count,
        "failed_ever":          failed_ever,
        "freq_24h":             freq_24h,
    }
