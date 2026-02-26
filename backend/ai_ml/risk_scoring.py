
import os
import pandas as pd
import numpy as np
from catboost import CatBoostClassifier

# Path to the trained model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "login_risk_model.cbm")

# Global model instance
_model = None

def get_model():
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = CatBoostClassifier()
            _model.load_model(MODEL_PATH)
        else:
            print(f"Warning: Model not found at {MODEL_PATH}. Prediction might fail.")
    return _model

def predict_risk(features):
    """
    Predicts risk using behavioral parameters:
    - device usage
    - geographic location
    - login frequency
    - failed login attempts (exceeding threshold)
    
    Risk Levels:
    - Normal (LOW): 1-2 attempts, same device/location.
    - Medium Risk: 3-4 attempts, or slight device/location change.
    - High Risk: Different location, unknown device, high freq, or >5 failed attempts.
    """
    history_count = features.get("history_count", 0)
    failed_attempts = features.get("failed_attempts", 0)
    
    # 1. High Risk Scenarios (Priority)
    # Block if: 5th+ attempt (history_count >= 4), or >5 failed attempts, or major deviations
    if (history_count >= 4 or
        failed_attempts >= 5 or 
        features["location_deviation"] > 0.8 or 
        features["device_deviation"] > 0.8 or 
        features["frequency_counts"]["24h"] >= 5):
        return {"level": "HIGH", "action": "BLOCK", "score": 95, "probability": 0.95}

    # 2. Medium Risk Scenarios
    # OTP if: 3rd or 4th attempt (history_count is 2 or 3), or moderate deviations
    if (history_count == 2 or history_count == 3) or (0.3 < features["location_deviation"] <= 0.8) or (0.3 < features["device_deviation"] <= 0.8):
        return {"level": "MEDIUM", "action": "OTP", "score": 55, "probability": 0.55}

    # 3. Normal / Low Risk (Default)
    # 1st and 2nd attempt (history_count is 0 or 1) from normal conditions
    return {"level": "LOW", "action": "ALLOW", "score": 15, "probability": 0.15}
