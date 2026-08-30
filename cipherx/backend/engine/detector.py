import asyncio
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from .adversarial import analyze_adversarial
from .brand import analyze_brand, trusted_domain_set
from .features import extract_features
from .lexical import analyze_lexical
from .ml_classifier import predict_ml_risk
from .network_intel import collect_network_intel, evaluate_network_safety
from .risk import score_risk
from .signals import make_signal
from .threat_intel import is_globally_trusted, lookup_threat_intel
from .url_utils import normalize_url


async def analyze_url(url: str, *, include_network: bool = True) -> dict:
    """
    Runs the CipherX explainable multi-layered URL detection pipeline:
    1. Host Network Safety & SSRF Evaluation
    2. Threat Intelligence Database & Live Feed Verification
    3. Feature Extraction & Lexical Analysis
    4. Adversarial Deception & Userinfo Analysis
    5. Brand Impersonation & Typosquatting Analysis
    6. Machine Learning Suspicious Pattern Classification
    7. Contextual Suppression & Explainable Scoring Engine
    """
    start_time = time.perf_counter()

    normalized = normalize_url(url)
    trusted = is_globally_trusted(normalized.registrable_domain)

    # 1. Feature Extraction
    features = extract_features(normalized)

    # 2. Host Network Safety Evaluation
    safety = evaluate_network_safety(normalized.hostname)
    ssrf_signals = []
    if not safety["safe_for_network_probe"] and "private_or_reserved_address" in safety["blocked_reasons"]:
        ssrf_signals.append(
            make_signal(
                "ssrf_attempt_blocked",
                "critical",
                100,
                f"SSRF Protection: Hostname resolves to private, loopback, or reserved IP address ({', '.join(safety['unsafe_addresses'] or [normalized.hostname])}).",
                {"blocked_reasons": safety["blocked_reasons"], "unsafe_addresses": safety["unsafe_addresses"]},
            )
        )

    # 3. Threat Intelligence Feeds & IOC Lookups
    threat_intel_signals, threat_intel_match = lookup_threat_intel(
        normalized.normalized_url,
        normalized.hostname,
        normalized.registrable_domain,
    )

    # 4. Lexical & Structural Analysis
    lexical_signals = analyze_lexical(normalized, features)

    # 5. Adversarial Analysis
    adversarial_signals, adversarial_findings = analyze_adversarial(
        normalized,
        features,
        trusted_domain_set(),
    )

    # 6. Brand Impersonation Analysis
    brand_signals, brand_analysis = analyze_brand(normalized, features)

    # 7. Machine Learning Classifier (Zero API Cost, skipped on trusted domains)
    ml_signals = []
    if not trusted:
        ml_result = predict_ml_risk(features)
        if ml_result and ml_result.get("score", 0) > 0:
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

    # 8. Suppress weak lexical noise on verified domains only when no stronger evidence exists.
    if (
        trusted
        and not threat_intel_match
        and not adversarial_findings
        and not has_contextual_lexical_evidence
    ):
        brand_signals = []
        lexical_signals = []
        ml_signals = []

    # IMPORTANT: Append brand subdomain deception findings AFTER suppression
    adversarial_findings.extend(_subdomain_deception_findings(brand_signals))

    # 9. Aggregate All Detected Evidence Signals
    all_signals = (
        ssrf_signals
        + threat_intel_signals
        + adversarial_signals
        + brand_signals
        + lexical_signals
        + ml_signals
    )
    signals = _deduplicate_signals(all_signals)

    risk_score, classification, confidence = score_risk(signals)

    # Verified whitelist override if trusted domain and no threat evidence survived
    if (
        trusted
        and not threat_intel_match
        and not adversarial_findings
        and not signals
    ):
        risk_score = 0
        classification = "LOW"
        confidence = 0.98

    features["trusted_base_domain"] = trusted
    if threat_intel_match:
        features["threat_intel_match"] = threat_intel_match

    # Collect Network Intelligence safely if requested
    network_info = None
    if include_network:
        network_info = await asyncio.to_thread(collect_network_intel, normalized)

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    features["scan_duration_ms"] = duration_ms

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
        "scan_duration_ms": duration_ms,
    }


def analyze_url_sync(url: str, *, include_network: bool = True) -> dict:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run,
                    analyze_url(url, include_network=include_network),
                ).result()
        return loop.run_until_complete(analyze_url(url, include_network=include_network))
    except Exception:
        return asyncio.run(analyze_url(url, include_network=include_network))


def _deduplicate_signals(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped = []
    seen = set()
    for signal in signals:
        details = signal.get("details") or {}
        key = (
            signal.get("signal"),
            json.dumps(details, sort_keys=True, default=str),
        )
        if key not in seen:
            deduped.append(signal)
            seen.add(key)
    return deduped


def _build_explanation(classification: str, signals: List[Dict[str, Any]], threat_intel_match: Optional[Dict[str, Any]] = None) -> str:
    if threat_intel_match:
        source = threat_intel_match.get("source", "Global Threat Feeds")
        threat_type = threat_intel_match.get("threat_type", "Malicious IOC")
        return f"CRITICAL risk: Confirmed malicious threat signature verified in {source} ({threat_type})."

    if not signals:
        return "No meaningful phishing or threat indicators detected from the URL alone."

    strongest = sorted(signals, key=lambda item: item.get("score", 0), reverse=True)[:3]
    reasons = "; ".join(signal["reason"] for signal in strongest)
    return f"{classification} risk based on {len(signals)} evidence signal(s): {reasons}"


def _subdomain_deception_findings(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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

