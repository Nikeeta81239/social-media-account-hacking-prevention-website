
import os
import pandas as pd
from catboost import CatBoostClassifier

# Path to the trained model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "login_risk_model.cbm")

def load_model():
    if not os.path.exists(MODEL_PATH):
        print(f"❌ Error: Model file not found at {MODEL_PATH}")
        print("Please run 'python backend/ai_ml/train_login_model.py' first.")
        return None
    
    try:
        model = CatBoostClassifier()
        model.load_model(MODEL_PATH)
        return model
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return None

def get_input(prompt, default=0.0):
    try:
        val = input(f"{prompt} (default {default}): ").strip()
        if not val:
            return float(default)
        return float(val)
    except ValueError:
        print("Invalid input. Using default.")
        return float(default)

def interactive_test():
    model = load_model()
    if not model:
        return

    print("\n" + "="*50)
    print("🛡️ AI CYBER SHIELD: INTERACTIVE MODEL TESTER")
    print("="*50)
    print("Enter values between 0.0 and 1.0 for deviations:")
    print("- 0.0 means 'Completely Normal/Matches History'")
    print("- 1.0 means 'Extremely Unusual/New Pattern'")
    print("-" * 50)

    try:
        while True:
            # 1. Gather Inputs
            time_dev = get_input("Time Deviation (0=normal hour, 1=12h shift)", 0.1)
            loc_dev  = get_input("Location Deviation (0=known city, 1=new country)", 0.0)
            dev_dev  = get_input("Device Deviation (0=trusted PC, 1=new phone)", 0.0)
            freq_dev = get_input("Frequency Deviation (0=normal, 1=high burst)", 0.05)

            # 2. Create DataFrame for prediction
            # Column order must match training: time_deviation, location_deviation, device_deviation, frequency_deviation
            df = pd.DataFrame([{
                'time_deviation': time_dev,
                'location_deviation': loc_dev,
                'device_deviation': dev_dev,
                'frequency_deviation': freq_dev
            }])

            # 3. Predict
            prob = model.predict_proba(df)[0][1]
            pred = model.predict(df)[0]
            risk_score = round(prob * 100, 2)

            # 4. Show Output
            print("\n" + "🔍 ANALYZING RISK...")
            print("-" * 30)
            if risk_score >= 70:
                print(f"🚨 STATUS: HIGH RISK (BLOCK)")
                print(f"📈 Risk Probability: {risk_score}%")
                print("Suggestion: Access should be DENIED immediately.")
            elif risk_score >= 31:
                print(f"⚠️ STATUS: MEDIUM RISK (OTP)")
                print(f"📈 Risk Probability: {risk_score}%")
                print("Suggestion: Trigger Two-Factor Authentication (OTP).")
            else:
                print(f"✅ STATUS: LOW RISK (ALLOW)")
                print(f"📈 Risk Probability: {risk_score}%")
                print("Suggestion: Pattern is consistent. Permit login.")
            
            print("-" * 30)
            cont = input("\nTest another input? (y/n): ").lower()
            if cont != 'y':
                break
            print("\n")

    except KeyboardInterrupt:
        print("\nExiting interactive tester.")

if __name__ == "__main__":
    interactive_test()
