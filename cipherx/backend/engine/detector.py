from .adversarial import analyze_adversarial
from .brand import analyze_brand, trusted_domain_set
from .features import extract_features
from .lexical import analyze_lexical
from .risk import score_risk
from .threat_intel import lookup_threat_intel, is_globally_trusted
from .url_utils import normalize_url
from .network_intel import collect_network_intel


def analyze_url(url: str) -> dict:
    """
    Runs the CipherX explainable multi-layered URL detection pipeline:
    1. Threat Intelligence Database & Live Feed Verification
    2. Feature Extraction & Lexical Analysis
    3. Adversarial Deception & Userinfo Analysis
    4. Brand Impersonation & Typosquatting Analysis
    5. Scoring & Explainable Reasoning Engine
    """
    normalized = normalize_url(url)
    features = extract_features(normalized)

    # 1. Threat Intelligence Feeds & IOC Lookups
    threat_intel_signals, threat_intel_match = lookup_threat_intel(
        normalized.normalized_url,
        normalized.hostname,
        normalized.registrable_domain,
    )

    # 2. Lexical & Structural Analysis
    lexical_signals = analyze_lexical(normalized, features)

    # 3. Adversarial Analysis
    adversarial_signals, adversarial_findings = analyze_adversarial(
        normalized,
        features,
        trusted_domain_set(),
    )

    # 4. Brand Impersonation Analysis
    brand_signals, brand_analysis = analyze_brand(normalized, features)
    adversarial_findings.extend(_subdomain_deception_findings(brand_signals))

    # 5. Offline Machine Learning Classifier (Zero API Cost)
    from .ml_classifier import predict_ml_risk
    from .signals import make_signal
    ml_signals = []
    ml_result = predict_ml_risk(features)
    if ml_result and ml_result.get("score", 0) > 0 and not is_globally_trusted(normalized.registrable_domain):
        ml_signals.append(
            make_signal(
                "ml_suspicious_url_pattern",
                ml_result["severity"],
                ml_result["score"],
                f"Offline ML classifier flagged URL features as suspicious (probability: {int(ml_result['ml_probability'] * 100)}%).",
                ml_result,
            )
        )
        features["ml_prediction"] = ml_result

    contextual_lexical_signals = {
        "embedded_url",
        "brand_reference_in_path",
        "url_shortener",
        "form_or_marketing_tracking",
        "abused_hosting_platform",
        "abused_platform_sensitive_context",
        "opaque_hosted_resource",
        "high_risk_file_extension",
    }
    has_contextual_lexical_evidence = any(
        signal.get("signal") in contextual_lexical_signals for signal in lexical_signals
    )

    # Suppress weak lexical noise on verified domains only when no stronger evidence exists.
    if (
        is_globally_trusted(normalized.registrable_domain)
        and not threat_intel_match
        and not adversarial_findings
        and not has_contextual_lexical_evidence
    ):
        brand_signals = []
        lexical_signals = []
        ml_signals = []

    # 6. Aggregate All Detected Evidence Signals
    all_signals = (
        threat_intel_signals
        + adversarial_signals
        + brand_signals
        + lexical_signals
        + ml_signals
    )
    signals = _deduplicate_signals(all_signals)

    risk_score, classification, confidence = score_risk(signals)


    # Add verified whitelist indicator if trusted domain and no stronger evidence survived.
    if (
        is_globally_trusted(normalized.registrable_domain)
        and not threat_intel_match
        and not adversarial_findings
        and not signals
    ):
        risk_score = 0
        classification = "LOW"
        confidence = 0.98

    # Attach threat intelligence match metadata into features for dashboard display
    features["trusted_base_domain"] = is_globally_trusted(normalized.registrable_domain)
    if threat_intel_match:
        features["threat_intel_match"] = threat_intel_match

    # Collect Network Intelligence by default
    network_info = collect_network_intel(normalized)

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
        "network": network_info,
        "explanation": _build_explanation(classification, signals, threat_intel_match),
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


def _build_explanation(classification, signals, threat_intel_match=None):
    if threat_intel_match:
        source = threat_intel_match.get("source", "Global Threat Feeds")
        threat_type = threat_intel_match.get("threat_type", "Malicious IOC")
        return f"CRITICAL risk: Confirmed malicious threat signature verified in {source} ({threat_type})."

    if not signals:
        return "No meaningful phishing or threat indicators detected from the URL alone."

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
