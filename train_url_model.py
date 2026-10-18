"""Train URL Phishing Classification Model.

Extracts lexical and structural URL features using URLDetector, trains a classifier
on labeled URL data, evaluates precision, recall, F1, and confusion matrix,
and serializes the trained model artifact to models/url_model.pkl.
"""

from __future__ import annotations

import argparse
import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
import joblib

from detector.url_detector import URLDetector


def validate_and_load_urls(filepath: str) -> pd.DataFrame:
    """Validate schema and clean input URL dataset."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"URL dataset file not found at: {filepath}")

    print(f"[*] Loading URL dataset from: {filepath}")
    df = pd.read_csv(filepath)

    required_columns = {"url", "label"}
    missing_cols = required_columns - set(df.columns)
    if missing_cols:
        raise ValueError(f"Dataset missing required column(s): {missing_cols}. Found: {list(df.columns)}")

    initial_count = len(df)
    print(f"[*] Initial raw URL count: {initial_count}")

    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["url"])

    cleaned_count = len(df)
    dropped = initial_count - cleaned_count
    if dropped > 0:
        print(f"[*] Dropped {dropped} duplicate/invalid records. Valid rows: {cleaned_count}")

    class_counts = df["label"].value_counts().to_dict()
    print(f"[*] Class distribution: 0 (Legitimate)={class_counts.get(0, 0)}, 1 (Phishing)={class_counts.get(1, 0)}")

    if len(class_counts) < 2:
        raise ValueError("URL dataset must contain both legitimate (0) and phishing (1) examples.")

    return df


def train_url_model(
    data_path: str = "data/url_dataset.csv",
    output_dir: str = "models",
    test_size: float = 0.25,
    random_state: int = 42,
) -> None:
    """Extract lexical features, train classifier, and save model."""
    os.makedirs(output_dir, exist_ok=True)
    df = validate_and_load_urls(data_path)

    print("[*] Extracting static lexical and structural features from URLs...")
    feature_vectors = []
    labels = []

    for _, row in df.iterrows():
        raw_url = str(row["url"])
        lbl = int(row["label"])
        try:
            feats = URLDetector.extract_features(raw_url)
            vec = URLDetector.feature_vector(feats)
            feature_vectors.append(vec)
            labels.append(lbl)
        except Exception as e:
            print(f"[!] Warning: Skipping malformed URL '{raw_url}': {e}")

    X = np.array(feature_vectors)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")
    print("[*] Training Random Forest URL classifier...")

    classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=random_state,
        class_weight="balanced",
    )
    classifier.fit(X_train, y_train)

    # Evaluation
    print("\n" + "=" * 55)
    print("           URL MODEL EVALUATION ON TEST SET")
    print("=" * 55)
    y_pred = classifier.predict(X_test)

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

    # Feature importances
    feature_names = [
        "url_length", "host_length", "dots_in_host", "hyphens_in_host",
        "is_ip", "is_shortener", "at_symbol", "double_slash",
        "unusual_port", "suspicious_tld", "keywords_count", "brands_count",
        "encoded_chars", "digit_ratio", "uses_https"
    ]
    importances = classifier.feature_importances_
    sorted_idx = np.argsort(importances)[::-1][:6]
    print("Top Influential Lexical Features:")
    for idx in sorted_idx:
        print(f"  - {feature_names[idx]:<20}: {importances[idx]:.4f}")

    model_output = os.path.join(output_dir, "url_model.pkl")
    joblib.dump(classifier, model_output)
    print(f"\n[+] URL Model saved to: {model_output}")
    print("=" * 55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AI Phishing URL Model")
    parser.add_argument(
        "--data",
        type=str,
        default="data/url_dataset.csv",
        help="Path to labeled CSV dataset (must have 'url' and 'label' columns).",
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="models",
        help="Directory to save trained model artifacts.",
    )
    args = parser.parse_args()

    try:
        train_url_model(data_path=args.data, output_dir=args.output_dir)
    except Exception as err:
        print(f"\n[!] URL model training failed: {err}", file=sys.stderr)
        sys.exit(1)
