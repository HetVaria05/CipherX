from urllib.parse import unquote

from .config import RISK_WEIGHTS, SUSPICIOUS_QUERY_KEYS
from .signals import make_signal


def analyze_lexical(normalized, features):
    signals = []
    decoded_path = unquote(normalized.path).lower()
    decoded_host = unquote(normalized.hostname).lower()

    if features["url_length"] > 120:
        signals.append(
            make_signal(
                "long_url",
                "low",
                RISK_WEIGHTS["long_url"],
                "URL length is unusually high for a typical destination link.",
                {"url_length": features["url_length"]},
            )
        )

    if features["subdomain_count"] >= 3:
        signals.append(
            make_signal(
                "excessive_subdomains",
                "medium",
                RISK_WEIGHTS["excessive_subdomains"],
                "Hostname contains several subdomain levels.",
                {"subdomain_count": features["subdomain_count"], "subdomain": normalized.subdomain},
            )
        )

    if normalized.registrable_domain.count("-") >= 2 or features["num_hyphens"] >= 4:
        signals.append(
            make_signal(
                "excessive_hyphens",
                "medium",
                RISK_WEIGHTS["excessive_hyphens"],
                "Domain or URL contains an unusual number of hyphens.",
                {"hyphens": features["num_hyphens"]},
            )
        )

    if features["digit_letter_ratio"] >= 0.25 and features["num_digits"] >= 3:
        signals.append(
            make_signal(
                "high_digit_ratio",
                "low",
                RISK_WEIGHTS["high_digit_ratio"],
                "URL contains a relatively high digit-to-letter ratio.",
                {"digit_letter_ratio": features["digit_letter_ratio"]},
            )
        )

    keyword_hits = [
        keyword
        for keyword in features["suspicious_keywords"]
        if keyword in decoded_host or keyword in decoded_path
    ]
    if keyword_hits:
        signals.append(
            make_signal(
                "login_or_verification_keyword",
                "medium",
                RISK_WEIGHTS["login_or_verification_keyword"],
                "URL contains account, login, or verification-related language.",
                {"keywords": keyword_hits},
            )
        )

    suspicious_query_keys = [
        key for key, value in normalized.query_parameters if key.lower() in SUSPICIOUS_QUERY_KEYS
    ]
    if suspicious_query_keys and _query_contains_urlish_value(normalized.query_parameters):
        signals.append(
            make_signal(
                "suspicious_query_parameter",
                "medium",
                RISK_WEIGHTS["suspicious_query_parameter"],
                "Query parameters include redirect-like fields carrying URL-shaped values.",
                {"parameters": sorted(set(suspicious_query_keys))},
            )
        )

    if features["suspicious_tld"]:
        signals.append(
            make_signal(
                "suspicious_tld",
                "medium",
                RISK_WEIGHTS["suspicious_tld"],
                "The top-level domain is frequently seen in low-reputation abuse patterns.",
                {"tld": normalized.tld},
            )
        )

    if features["domain_entropy"] >= 3.5 and len(normalized.registrable_domain) >= 14:
        signals.append(
            make_signal(
                "high_domain_entropy",
                "low",
                RISK_WEIGHTS["high_domain_entropy"],
                "Domain character distribution is unusually random-looking.",
                {"domain_entropy": features["domain_entropy"]},
            )
        )

    encoded_values = set(features["encoded_values"])
    if encoded_values:
        sensitive = sorted(encoded_values.intersection({"%2F", "%3A", "%40", "%5C"}))
        if sensitive:
            signals.append(
                make_signal(
                    "encoded_sensitive_character",
                    "medium",
                    RISK_WEIGHTS["encoded_sensitive_character"],
                    "URL contains percent-encoded reserved characters that can obscure structure.",
                    {"encoded_values": sensitive},
                )
            )
        else:
            signals.append(
                make_signal(
                    "encoded_characters",
                    "low",
                    RISK_WEIGHTS["encoded_characters"],
                    "URL contains percent-encoded characters.",
                    {"encoded_values": sorted(encoded_values)},
                )
            )

    if features["suspicious_port"]:
        signals.append(
            make_signal(
                "suspicious_special_structure",
                "medium",
                RISK_WEIGHTS["suspicious_special_structure"],
                "URL uses a non-standard port often associated with temporary infrastructure.",
                {"port": normalized.port},
            )
        )

    if not features["uses_https"] and (
        features["has_ip"] or any(keyword in decoded_path for keyword in ("login", "signin", "verify"))
    ):
        signals.append(
            make_signal(
                "http_with_sensitive_context",
                "medium",
                RISK_WEIGHTS["http_with_sensitive_context"],
                "Sensitive-looking destination is not using HTTPS.",
                {"scheme": normalized.scheme},
            )
        )

    return signals


def _query_contains_urlish_value(parameters):
    for _, value in parameters:
        lowered = unquote(value).lower()
        if "://" in lowered or lowered.startswith(("http", "www.")) or "." in lowered:
            return True
    return False
