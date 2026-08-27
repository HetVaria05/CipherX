"""
CipherX Machine Learning Model Trainer
=======================================
Trains a lightweight, high-performance offline classifier on URL features.
Uses the CipherX feature extraction pipeline to turn raw URLs into tabular vectors.

Usage:
    python backend/scripts/train_model.py --dataset backend/data/url_dataset.csv --algorithm random_forest
"""

import argparse
import json
import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
import joblib

# Ensure backend root is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from engine.url_utils import normalize_url
from engine.features import extract_features

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "domain_length",
    "subdomain_count",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "digit_letter_ratio",
    "path_length",
    "query_param_count",
    "special_character_count",
    "has_at_symbol",
    "has_ip",
    "uses_https",
    "suspicious_port",
    "encoded_characters",
    "suspicious_keyword_count",
    "embedded_url_count",
    "is_url_shortener",
    "is_abused_hosting_platform",
    "is_marketing_or_form_platform",
    "path_segment_count",
    "longest_path_segment",
    "opaque_path_token_count",
    "has_high_risk_file_extension",
    "domain_entropy",
    "domain_complexity",
    "suspicious_tld",
]


def extract_row_features(url: str) -> dict:
    """Extracts numeric/boolean feature dictionary for tabular ML training."""
    try:
        norm = normalize_url(str(url).strip())
        feat = extract_features(norm)
        return {
            "url_length": feat["url_length"],
            "hostname_length": feat["hostname_length"],
            "domain_length": feat["domain_length"],
            "subdomain_count": feat["subdomain_count"],
            "num_dots": feat["num_dots"],
            "num_hyphens": feat["num_hyphens"],
            "num_digits": feat["num_digits"],
            "digit_letter_ratio": float(feat["digit_letter_ratio"]),
            "path_length": feat["path_length"],
            "query_param_count": feat["query_param_count"],
            "special_character_count": feat["special_character_count"],
            "has_at_symbol": 1 if feat["has_at_symbol"] else 0,
            "has_ip": 1 if feat["has_ip"] else 0,
            "uses_https": 1 if feat["uses_https"] else 0,
            "suspicious_port": 1 if feat["suspicious_port"] else 0,
            "encoded_characters": feat["encoded_characters"],
            "suspicious_keyword_count": len(feat.get("suspicious_keywords", [])),
            "embedded_url_count": len(feat.get("embedded_urls", [])),
            "is_url_shortener": 1 if feat["is_url_shortener"] else 0,
            "is_abused_hosting_platform": 1 if feat["is_abused_hosting_platform"] else 0,
            "is_marketing_or_form_platform": 1 if feat["is_marketing_or_form_platform"] else 0,
            "path_segment_count": feat["path_segment_count"],
            "longest_path_segment": feat["longest_path_segment"],
            "opaque_path_token_count": feat["opaque_path_token_count"],
            "has_high_risk_file_extension": 1 if feat["has_high_risk_file_extension"] else 0,
            "domain_entropy": float(feat["domain_entropy"]),
            "domain_complexity": float(feat["domain_complexity"]),
            "suspicious_tld": 1 if feat["suspicious_tld"] else 0,
        }
    except Exception:
        # Fallback empty vector
        return {col: 0 for col in FEATURE_COLUMNS}


def load_dataset(file_path: str) -> pd.DataFrame:
    """Loads CSV or JSON dataset of URLs with 'url' and 'label' (0 or 1, or 'benign'/'malicious')."""
    print(f"[*] Loading dataset from: {file_path}")
    if file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
    elif file_path.endswith(".json"):
        df = pd.read_json(file_path)
    else:
        raise ValueError("Unsupported format. Use CSV or JSON.")

    # Standardize column names
    col_map = {col: col.lower().strip() for col in df.columns}
    df = df.rename(columns=col_map)

    url_col = next((c for c in df.columns if "url" in c), None)
    label_col = next((c for c in df.columns if "label" in c or "type" in c or "target" in c or "class" in c), None)

    if not url_col or not label_col:
        raise ValueError(f"Dataset must contain a URL column and a Label column. Found: {list(df.columns)}")

    df = df[[url_col, label_col]].dropna().drop_duplicates(subset=[url_col])
    df = df.rename(columns={url_col: "url", label_col: "label"})

    # Map labels to 0 (benign) and 1 (malicious)
    if df["label"].dtype == object:
        df["label"] = df["label"].astype(str).str.lower().map(
            lambda x: 0 if x in ["0", "benign", "safe", "legitimate", "good", "clean"] else 1
        )

    print(f"[+] Loaded {len(df)} unique records (Benign: {sum(df['label'] == 0)}, Malicious: {sum(df['label'] == 1)})")
    return df


def train_classifier(df: pd.DataFrame, algorithm: str = "random_forest", output_dir: str = None):
    """Extracts features, trains the model, logs evaluation, and exports joblib artifact."""
    print("[*] Extracting 28 feature vectors for all dataset URLs...")
    feature_rows = [extract_row_features(u) for u in df["url"]]
    X = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print(f"[*] Training model using '{algorithm}' on {len(X_train)} samples...")
    if algorithm == "gradient_boosting":
        model = GradientBoostingClassifier(n_estimators=200, learning_rate=0.1, max_depth=6, random_state=42)
    else:
        model = RandomForestClassifier(n_estimators=250, max_depth=16, random_state=42, n_jobs=-1)

    model.fit(X_train, y_train)

    # Evaluation
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred

    auc = roc_auc_score(y_test, y_prob)
    print("\n" + "=" * 50)
    print("           MODEL EVALUATION REPORT")
    print("=" * 50)
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Malicious (1)"]))
    print(f"ROC-AUC Score: {auc:.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("=" * 50)

    # Save artifact
    if not output_dir:
        output_dir = os.path.join(backend_dir, "models")
    os.makedirs(output_dir, exist_ok=True)

    artifact_path = os.path.join(output_dir, "url_classifier.joblib")
    meta_path = os.path.join(output_dir, "model_meta.json")

    joblib.dump(model, artifact_path)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({
            "algorithm": algorithm,
            "feature_columns": FEATURE_COLUMNS,
            "roc_auc": round(float(auc), 4),
            "samples_trained": len(df),
        }, f, indent=2)

    print(f"[+] Model artifact saved to: {artifact_path}")
    print(f"[+] Metadata saved to: {meta_path}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CipherX ML Model Trainer")
    parser.add_argument("--dataset", type=str, required=False, default=os.path.join(backend_dir, "data", "url_dataset.csv"), help="Path to CSV/JSON dataset")
    parser.add_argument("--algorithm", type=str, default="random_forest", choices=["random_forest", "gradient_boosting"], help="Algorithm to train")
    args = parser.parse_args()

    if os.path.exists(args.dataset):
        df_data = load_dataset(args.dataset)
        train_classifier(df_data, algorithm=args.algorithm)
    else:
        print(f"[-] Dataset file not found at: {args.dataset}")
        print("[!] Once your dataset is saved in backend/data/url_dataset.csv, re-run this script to generate model weights.")
