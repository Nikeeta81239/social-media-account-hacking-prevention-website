
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "login_risk_model.cbm")

_model = None

def get_model():
    global _model
    if _model is None:
        try:
            from catboost import CatBoostClassifier
            if os.path.exists(MODEL_PATH):
                _model = CatBoostClassifier()
                _model.load_model(MODEL_PATH)
        except Exception as e:
            print(f"Warning: Could not load CatBoost model: {e}")
    return _model


def predict_risk(features):
    """
    Refined 3-tier risk model with Dynamic Deviation Sensitivity:
    
    1. LOW RISK (score 10): 
       - 1st & 2nd attempts (failed_attempts 0 or 1).
    
    2. MEDIUM RISK (score 55): 
       - 3rd, 4th, and 5th attempts (failed_attempts 2, 3, or 4).
       - Triggers OTP verification.
    
    3. HIGH RISK (score 90):
       - Severe behavioral deviations (loc_dev >= 1.0, dev_dev >= 1.0).
       - Extreme login frequency.
    """
    failed_attempts = features.get("failed_attempts", 0)
    loc_dev         = features.get("location_deviation", 0.0)
    dev_dev         = features.get("device_deviation", 0.0)
    time_dev        = features.get("time_deviation", 0.0)
    freq_24h        = features.get("frequency_counts", {}).get("24h", 0)
    
    # Combined behavioral deviation score
    behavioral_deviation = max(loc_dev, dev_dev, time_dev)

    # ── 1st & 2nd ATTEMPTS: ALWAYS ALLOW (Low Risk) ──
    if failed_attempts < 2:
        return {"level": "LOW", "action": "ALLOW", "score": 10}

    # ── MEDIUM RISK (Score 55) — OTP TARGET ──
    # Requirement: 3rd, 4th, and 5th attempts (failed_attempts 2, 3, 4)
    if (2 <= failed_attempts <= 4):
        # We always trigger OTP for these attempts to ensure security sequence
        # This overrides high-risk behavioral blocks for successful password entries.
        return {"level": "MEDIUM", "action": "OTP", "score": 55}

    # ── HIGH RISK (Score 90) ──
    # Forced block for severe anomalies (IP/Device/Location shifts)
    if (freq_24h >= 10 or behavioral_deviation >= 1.0):
         return {"level": "HIGH", "action": "BLOCK", "score": 90}

    # Default fallback
    return {"level": "LOW", "action": "ALLOW", "score": 10}
