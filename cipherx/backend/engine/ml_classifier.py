import os
import json
import logging
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger(__name__)

_model = None
_meta = None

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "url_classifier.joblib")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")


def load_ml_model():
    """Loads the trained ML model into memory once."""
    global _model, _meta
    if _model is not None:
        return _model, _meta

    if os.path.exists(MODEL_PATH):
        try:
            import joblib
            _model = joblib.load(MODEL_PATH)
            if os.path.exists(META_PATH):
                with open(META_PATH, "r", encoding="utf-8") as f:
                    _meta = json.load(f)
            logger.info("Successfully loaded offline ML URL classifier.")
        except Exception as err:
            logger.warning(f"Could not load ML model ({err}). ML evaluation will be skipped.")
            _model = None
            _meta = None
    return _model, _meta



def predict_ml_risk(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Evaluates extracted features against the trained ML model.
    Returns ML probability, calibrated risk contribution, and top factors.
    """
    model, meta = load_ml_model()
    if model is None or meta is None:
        return None

    try:
        import pandas as pd
    except ImportError:
        return None

    feature_cols = meta.get("feature_columns", [])
    try:

        row = {
            "url_length": features.get("url_length", 0),
            "hostname_length": features.get("hostname_length", 0),
            "domain_length": features.get("domain_length", 0),
            "subdomain_count": features.get("subdomain_count", 0),
            "num_dots": features.get("num_dots", 0),
            "num_hyphens": features.get("num_hyphens", 0),
            "num_digits": features.get("num_digits", 0),
            "digit_letter_ratio": float(features.get("digit_letter_ratio", 0)),
            "path_length": features.get("path_length", 0),
            "query_param_count": features.get("query_param_count", 0),
            "special_character_count": features.get("special_character_count", 0),
            "has_at_symbol": 1 if features.get("has_at_symbol") else 0,
            "has_ip": 1 if features.get("has_ip") else 0,
            "uses_https": 1 if features.get("uses_https") else 0,
            "suspicious_port": 1 if features.get("suspicious_port") else 0,
            "encoded_characters": features.get("encoded_characters", 0),
            "suspicious_keyword_count": len(features.get("suspicious_keywords", [])),
            "embedded_url_count": len(features.get("embedded_urls", [])),
            "is_url_shortener": 1 if features.get("is_url_shortener") else 0,
            "is_abused_hosting_platform": 1 if features.get("is_abused_hosting_platform") else 0,
            "is_marketing_or_form_platform": 1 if features.get("is_marketing_or_form_platform") else 0,
            "path_segment_count": features.get("path_segment_count", 0),
            "longest_path_segment": features.get("longest_path_segment", 0),
            "opaque_path_token_count": features.get("opaque_path_token_count", 0),
            "has_high_risk_file_extension": 1 if features.get("has_high_risk_file_extension") else 0,
            "domain_entropy": float(features.get("domain_entropy", 0)),
            "domain_complexity": float(features.get("domain_complexity", 0)),
            "suspicious_tld": 1 if features.get("suspicious_tld") else 0,
        }

        df = pd.DataFrame([row], columns=feature_cols)
        prob = float(model.predict_proba(df)[0][1]) if hasattr(model, "predict_proba") else float(model.predict(df)[0])
        
        # Determine risk signal
        severity = "low"
        score = 0
        if prob >= 0.85:
            severity = "critical"
            score = 65
        elif prob >= 0.65:
            severity = "high"
            score = 45
        elif prob >= 0.45:
            severity = "medium"
            score = 25

        return {
            "ml_probability": round(prob, 4),
            "score": score,
            "severity": severity,
            "algorithm": meta.get("algorithm", "ensemble"),
            "roc_auc": meta.get("roc_auc", 0.0),
        }
    except Exception as err:
        logger.error(f"Error during ML inference ({err})")
        return None
