"""Train Message Phishing Detection Model.

Loads, validates, and preprocesses the message dataset, trains a TF-IDF
vectorizer with a Logistic Regression classifier, evaluates precision, recall,
F1-score, and confusion matrix, and saves the serialized model artifacts.
"""

from __future__ import annotations

import argparse
import os
import sys
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
import joblib


def validate_and_load_data(filepath: str) -> pd.DataFrame:
    """Validate schema, handle missing records, and load the dataset."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset file not found at: {filepath}")

    print(f"[*] Loading dataset from: {filepath}")
    df = pd.read_csv(filepath)

    required_columns = {"text", "label"}
    missing_cols = required_columns - set(df.columns)
    if missing_cols:
        raise ValueError(f"Dataset missing required column(s): {missing_cols}. Found: {list(df.columns)}")

    initial_count = len(df)
    print(f"[*] Initial raw record count: {initial_count}")

    # Drop missing values
    df = df.dropna(subset=["text", "label"])

    # Ensure label is integer (0 = Legitimate, 1 = Phishing)
    df["label"] = df["label"].astype(int)

    # Remove duplicate texts
    df = df.drop_duplicates(subset=["text"])
    cleaned_count = len(df)
    dropped = initial_count - cleaned_count
    if dropped > 0:
        print(f"[*] Dropped {dropped} duplicate or invalid rows. Valid rows remaining: {cleaned_count}")

    # Class balance check
    class_counts = df["label"].value_counts().to_dict()
    print(f"[*] Class distribution: 0 (Legitimate)={class_counts.get(0, 0)}, 1 (Phishing)={class_counts.get(1, 0)}")

    if len(class_counts) < 2:
        raise ValueError("Dataset must contain both classes (0 and 1) to train a classification model.")

    return df


def train_message_model(
    data_path: str = "data/message_dataset.csv",
    models_dir: str = "models",
    test_size: float = 0.25,
    random_state: int = 42,
) -> None:
    """Train the TF-IDF vectorizer and classifier, evaluate metrics, and save artifacts."""
    os.makedirs(models_dir, exist_ok=True)
    df = validate_and_load_data(data_path)

    X = df["text"].astype(str)
    y = df["label"].values

    # Stratified train/test split to preserve class proportions
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # 1. Feature Extraction: TF-IDF with unigrams + bigrams and sublinear term frequency
    print("[*] Vectorizing text with TF-IDF...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        max_features=5000,
        stop_words="english",
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 2. Classifier: Logistic Regression with balanced class weights
    print("[*] Training Logistic Regression classifier...")
    classifier = LogisticRegression(
        C=1.0,
        max_iter=1000,
        random_state=random_state,
        class_weight="balanced",
    )
    classifier.fit(X_train_vec, y_train)

    # 3. Model Evaluation on Holdout Test Set
    print("\n" + "=" * 55)
    print("           MODEL EVALUATION ON TEST SET")
    print("=" * 55)
    y_pred = classifier.predict(X_test_vec)

    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"Precision (Phishing class 1): {prec:.4f}")
    print(f"Recall    (Phishing class 1): {rec:.4f}")
    print(f"F1-Score  (Phishing class 1): {f1:.4f}\n")

    print("Confusion Matrix:")
    print("                 Predicted Legitimate (0)  Predicted Phishing (1)")
    print(f"Actual Legitimate (0)      {cm[0][0]:<25} {cm[0][1]}")
    print(f"Actual Phishing   (1)      {cm[1][0]:<25} {cm[1][1]}")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"]))

    # 4. Save Artifacts using joblib
    model_output = os.path.join(models_dir, "message_model.pkl")
    vect_output = os.path.join(models_dir, "message_vectorizer.pkl")

    joblib.dump(classifier, model_output)
    joblib.dump(vectorizer, vect_output)

    print(f"[+] Model successfully saved to:      {model_output}")
    print(f"[+] Vectorizer successfully saved to: {vect_output}")
    print("=" * 55)
    print("[*] Ready for Flask application inference.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AI Phishing Message Model")
    parser.add_argument(
        "--data",
        type=str,
        default="data/message_dataset.csv",
        help="Path to labeled CSV dataset (must have 'text' and 'label' columns).",
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="models",
        help="Directory to save trained model artifacts.",
    )
    args = parser.parse_args()

    try:
        train_message_model(data_path=args.data, models_dir=args.output_dir)
    except Exception as err:
        print(f"\n[!] Training failed: {err}", file=sys.stderr)
        sys.exit(1)
