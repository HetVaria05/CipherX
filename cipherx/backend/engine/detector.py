from .adversarial import analyze_adversarial
from .brand import analyze_brand, trusted_domain_set
from .features import extract_features
from .lexical import analyze_lexical
from .risk import score_risk
from .url_utils import normalize_url


def analyze_url(url: str) -> dict:
    """
    Runs the CipherX explainable rule-based URL detection pipeline.
    """
    normalized = normalize_url(url)
    features = extract_features(normalized)

    lexical_signals = analyze_lexical(normalized, features)
    adversarial_signals, adversarial_findings = analyze_adversarial(
        normalized,
        features,
        trusted_domain_set(),
    )
    brand_signals, brand_analysis = analyze_brand(normalized, features)
    adversarial_findings.extend(_subdomain_deception_findings(brand_signals))

    signals = _deduplicate_signals(
        lexical_signals
        + adversarial_signals
        + brand_signals
    )
    risk_score, classification, confidence = score_risk(signals)

    return {
        "url": normalized.original_url,
        "normalized_url": normalized.normalized_url,
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "signals": signals,
        "features": features,
        "adversarial_findings": adversarial_findings,
        "brand_analysis": brand_analysis,
        "explanation": _build_explanation(classification, signals),
    }


def _deduplicate_signals(signals):
    deduped = []
    seen = set()
    for signal in signals:
        key = (
            signal.get("signal"),
            repr(sorted((signal.get("details") or {}).items())),
        )
        if key not in seen:
            deduped.append(signal)
            seen.add(key)
    return deduped


def _build_explanation(classification, signals):
    if not signals:
        return "No meaningful phishing indicators were detected by the current rule-based engine."

    strongest = sorted(signals, key=lambda item: item.get("score", 0), reverse=True)[:3]
    reasons = "; ".join(signal["reason"] for signal in strongest)
    return f"{classification} risk based on {len(signals)} evidence signal(s): {reasons}"


def _subdomain_deception_findings(signals):
    findings = []
    for signal in signals:
        if signal.get("signal") != "brand_subdomain_deception":
            continue
        details = signal.get("details") or {}
        findings.append(
            {
                "technique": "subdomain_brand_deception",
                "severity": signal.get("severity", "high"),
                "actual_domain": details.get("analyzed_domain"),
                "deceptive_domain": details.get("official_domain"),
                "brand": details.get("brand"),
                "reason": signal.get("reason"),
            }
        )
    return findings
