# ================================
# AI-Based Social Account Detection
# CatBoost + ELI5 + LIME
# Fully Safe & Viva-Ready
# ================================

import os
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from catboost import CatBoostClassifier

import eli5
from eli5.sklearn import PermutationImportance

from lime.lime_tabular import LimeTabularExplainer

# ================================
# 🔹 PATH TO DATA FOLDER
# ================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "data")

if not os.path.exists(DATASET_DIR):
    raise FileNotFoundError(f"Data folder not found at: {DATASET_DIR}")

# ================================
# 🔹 HELPER FUNCTION: LOAD CSV
# ================================
def load_dataset(file_name):
    path = os.path.join(DATASET_DIR, file_name)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Dataset file not found: {path}")
    print(f"✔ Loaded dataset: {path}")
    return pd.read_csv(path)

# ================================
# 🔹 LOAD DATASETS
# ================================
bot_df = load_dataset("bot_detection_data.csv")
hybrid_df = load_dataset("hybridDataset.csv")
insta_df = load_dataset("instagram_fake_profile_dataset.csv")

# ================================
# 🔹 SHOW COLUMNS
# ================================
def show_columns(df, name):
    print(f"\n📌 {name} COLUMNS:")
    print(df.columns.tolist())

show_columns(bot_df, "Bot Dataset")
show_columns(hybrid_df, "Hybrid Dataset")
show_columns(insta_df, "Instagram Fake Dataset")

# ================================
# 🔹 TRAIN + EXPLAIN FUNCTION
# ================================
def train_and_explain(df, target_column, dataset_name="Dataset"):
    print(f"\n==================== {dataset_name} ====================")

    # Drop rows where target is NaN
    df = df.dropna(subset=[target_column])

    # ----------------------------
    # Select numeric features only
    # ----------------------------
    X = df.select_dtypes(include=[np.number]).drop(columns=[target_column], errors='ignore')
    y = df[target_column]

    if X.shape[1] == 0:
        raise ValueError(f"No numeric features found in {dataset_name} to train CatBoost!")

    # Fill missing values
    X = X.fillna(0)
    y = y.fillna(0)

    print("✅ Using numeric features only for CatBoost:")
    print(X.columns.tolist())

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ----------------------------
    # Train CatBoost Classifier
    # ----------------------------
    model = CatBoostClassifier(
        iterations=300,
        learning_rate=0.1,
        depth=6,
        verbose=0,
        random_state=42
    )
    model.fit(X_train, y_train)

    # ----------------------------
    # Predictions + Metrics
    # ----------------------------
    y_pred = model.predict(X_test)
    print("\n✅ Accuracy:", accuracy_score(y_test, y_pred))
    print("\n📝 Classification Report:\n", classification_report(y_test, y_pred))
    print("\n🔲 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    # ----------------------------
    # ELI5 Permutation Importance
    # ----------------------------
    print("\n💡 ELI5 Permutation Feature Importance:")
    perm = PermutationImportance(model, random_state=42).fit(X_test, y_test)
    print(eli5.format_as_text(eli5.explain_weights(perm, feature_names=X.columns.tolist())))

    # ----------------------------
    # LIME Explanation for first test instance
    # ----------------------------
    print("\n🔍 LIME Explanation for first numeric test instance:")
    explainer = LimeTabularExplainer(
        X_train.values,
        feature_names=X.columns.tolist(),
        class_names=[str(c) for c in np.unique(y_train)],
        discretize_continuous=True,
        random_state=42
    )
    exp = explainer.explain_instance(
        X_test.values[0],
        model.predict_proba,
        num_features=min(10, X_test.shape[1])
    )
    print(exp.as_list())

    return model

# ================================
# 🔹 MAIN EXECUTION
# ================================
if __name__ == "__main__":
    BOT_TARGET = "Bot Label"
    HYBRID_TARGET = "category"
    INSTA_TARGET = "fake"

    bot_model = train_and_explain(bot_df, BOT_TARGET, "Bot Detection Dataset")
    hybrid_model = train_and_explain(hybrid_df, HYBRID_TARGET, "Hybrid Dataset")
    insta_model = train_and_explain(insta_df, INSTA_TARGET, "Instagram Fake Dataset")

    print("\n🔥 Training & explanations completed successfully for all datasets!")
