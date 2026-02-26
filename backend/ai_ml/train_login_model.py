
import os
import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
import pickle

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "login_risk_model.cbm")

def generate_synthetic_login_data(n_samples=5000):
    np.random.seed(42)
    
    # Features (Normalized Deviations 0 to 1)
    # Login time deviation (0=normal time, 1=very unusual)
    time_dev = np.random.beta(2, 5, n_samples) 
    
    # Location deviation (0=usual, 1=new country)
    loc_dev = np.random.choice([0, 1], n_samples, p=[0.8, 0.2])
    
    # Device deviation
    dev_dev = np.random.choice([0, 1], n_samples, p=[0.85, 0.15])
    
    # Engagement/Frequency deviation (simulated)
    freq_dev = np.random.beta(2, 5, n_samples)
    
    # Create target (Risk)
    # Risk increases with deviations
    risk_score = (time_dev * 0.3) + (loc_dev * 0.4) + (dev_dev * 0.2) + (freq_dev * 0.1) + np.random.normal(0, 0.05, n_samples)
    
    # Label: 1 if risk_score > 0.5 (Suspicious), else 0
    target = (risk_score > 0.45).astype(int)
    
    df = pd.DataFrame({
        'time_deviation': time_dev,
        'location_deviation': loc_dev,
        'device_deviation': dev_dev,
        'frequency_deviation': freq_dev,
        'risk_label': target
    })
    
    return df

def train_login_model():
    print("Generating synthetic login deviation dataset...")
    df = generate_synthetic_login_data()
    
    X = df.drop('risk_label', axis=1)
    y = df['risk_label']
    
    print("Training CatBoost Classifier...")
    model = CatBoostClassifier(
        iterations=500,
        learning_rate=0.05,
        depth=6,
        loss_function='Logloss',
        verbose=False,
        random_state=42
    )
    
    model.fit(X, y)
    
    # Save model
    model.save_model(MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_login_model()
