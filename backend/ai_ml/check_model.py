
import os
import sys
import pandas as pd
from catboost import CatBoostClassifier

# Add current directory to path if needed
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "login_risk_model.cbm")

def test_model_loading():
    print("-" * 50)
    print(f"🔍 Checking model at: {MODEL_PATH}")
    if not os.path.exists(MODEL_PATH):
        print("❌ Error: Model file not found!")
        return False
    
    try:
        model = CatBoostClassifier()
        model.load_model(MODEL_PATH)
        print("✅ Success: Model loaded successfully.")
        return model
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False

def test_prediction(model):
    if not model:
        return
    
    # Feature order: 'time_deviation', 'location_deviation', 'device_deviation', 'frequency_deviation'
    # Based on train_login_model.py
    
    cases = [
        {
            "name": "Normal Login (Safe)",
            "data": {'time_deviation': 0.1, 'location_deviation': 0.0, 'device_deviation': 0.0, 'frequency_deviation': 0.05}
        },
        {
            "name": "Highly Suspicious (Threat)",
            "data": {'time_deviation': 0.9, 'location_deviation': 1.0, 'device_deviation': 1.0, 'frequency_deviation': 0.8}
        },
        {
            "name": "Partial Deviation (Warning)",
            "data": {'time_deviation': 0.4, 'location_deviation': 0.0, 'device_deviation': 1.0, 'frequency_deviation': 0.1}
        }
    ]
    
    print("\n🚀 Running model prediction test cases:")
    print("-" * 50)
    
    results = []
    for c in cases:
        df = pd.DataFrame([c["data"]])
        prob = model.predict_proba(df)[0][1] # Probability of being 'Suspicious' (Class 1)
        pred = model.predict(df)[0]
        risk_pct = round(prob * 100, 2)
        
        status = "🔴 SUSPICIOUS" if pred == 1 else "🟢 SAFE"
        print(f"Case: {c['name']}")
        print(f"  Inputs: {c['data']}")
        print(f"  Result: {status} | Risk Score: {risk_pct}%")
        print("-" * 30)
        results.append((c['name'], risk_pct))

    # Verification
    if results[1][1] > results[0][1]:
        print("\n✅ FINAL VERIFICATION: MODEL IS FUNCTIONAL.")
        print("It correctly identifies high-risk anomalous behavior.")
    else:
        print("\n⚠️ VERIFICATION FAILED: Model is not discriminating properly.")

if __name__ == "__main__":
    loaded_model = test_model_loading()
    if loaded_model:
        test_prediction(loaded_model)
