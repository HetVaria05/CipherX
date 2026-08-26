from urllib.parse import unquote

from .config import RISK_WEIGHTS, SUSPICIOUS_QUERY_KEYS, TRUSTED_BRANDS
from .signals import make_signal


def analyze_lexical(normalized, features):
    signals = []
    decoded_path = unquote(normalized.path).lower()
    decoded_host = unquote(normalized.hostname).lower()
    decoded_query = unquote(normalized.query).lower()
    decoded_path_query = f"{decoded_path}?{decoded_query}"

    if features["embedded_domains"]:
        signals.append(
            make_signal(
                "embedded_url",
                "high",
                RISK_WEIGHTS["embedded_url"],
                "URL contains an embedded or encoded destination that differs from the visible hostname.",
                {
                    "embedded_domains": features["embedded_domains"],
                    "embedded_urls": features["embedded_urls"][:3],
                },
            )
        )

    brand_references = _brand_references_in_path_or_query(normalized, decoded_path_query)
    if brand_references:
        signals.append(
            make_signal(
                "brand_reference_in_path",
                "high",
                RISK_WEIGHTS["brand_reference_in_path"],
                "A trusted brand domain appears in the path or query instead of the actual destination hostname.",
                {"brand_references": brand_references},
            )
        )

    if features["is_url_shortener"]:
        signals.append(
            make_signal(
                "url_shortener",
                "medium",
                RISK_WEIGHTS["url_shortener"],
                "URL uses a link-shortening or redirect service that hides the final destination.",
                {"hostname": normalized.hostname},
            )
        )

    if features["is_marketing_or_form_platform"] and _has_platform_tracking_shape(normalized, features):
        signals.append(
            make_signal(
                "form_or_marketing_tracking",
                "medium",
                RISK_WEIGHTS["form_or_marketing_tracking"],
                "URL points to a form, document, or marketing platform with campaign/form tracking identifiers.",
                {
                    "hostname": normalized.hostname,
                    "query_param_count": features["query_param_count"],
                    "opaque_path_token_count": features["opaque_path_token_count"],
                },
            )
        )

    if features["is_abused_hosting_platform"]:
        signals.append(
            make_signal(
                "abused_hosting_platform",
                "low",
                RISK_WEIGHTS["abused_hosting_platform"],
                "URL is hosted on a free/developer publishing platform often abused for phishing pages.",
                {"hostname": normalized.hostname, "registrable_domain": normalized.registrable_domain},
            )
        )
        if features["suspicious_keywords"] or features["opaque_path_token_count"] or _has_sensitive_platform_language(decoded_host, decoded_path_query):
            signals.append(
                make_signal(
                    "abused_platform_sensitive_context",
                    "medium",
                    RISK_WEIGHTS["abused_platform_sensitive_context"],
                    "Hosted platform URL also contains credential, wallet, payment, or opaque resource indicators.",
                    {
                        "keywords": features["suspicious_keywords"],
                        "opaque_path_token_count": features["opaque_path_token_count"],
                    },
                )
            )

    if (
        (features["is_abused_hosting_platform"] or features["is_marketing_or_form_platform"])
        and features["opaque_path_token_count"] > 0
    ):
        signals.append(
            make_signal(
                "opaque_hosted_resource",
                "medium",
                RISK_WEIGHTS["opaque_hosted_resource"],
                "Hosted-platform URL contains long random-looking path tokens typical of generated phishing forms.",
                {
                    "opaque_path_token_count": features["opaque_path_token_count"],
                    "longest_path_segment": features["longest_path_segment"],
                },
            )
        )
    elif features["opaque_path_token_count"] > 0:
        signals.append(
            make_signal(
                "random_path_tokens",
                "medium",
                RISK_WEIGHTS["random_path_tokens"],
                "URL contains randomized or generated alphanumeric path routing identifiers typical of phishing campaigns.",
                {
                    "opaque_path_token_count": features["opaque_path_token_count"],
                    "longest_path_segment": features["longest_path_segment"],
                },
            )
        )

    if features["has_high_risk_file_extension"]:
        signals.append(
            make_signal(
                "high_risk_file_extension",
                "high",
                RISK_WEIGHTS["high_risk_file_extension"],
                "URL directly references an executable or script file type commonly used for malware delivery.",
                {"extension": features["high_risk_file_extension"]},
            )
        )

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

    if not features["uses_https"]:
        signals.append(
            make_signal(
                "insecure_http_transport",
                "high",
                RISK_WEIGHTS["insecure_http_transport"],
                "Website uses unencrypted HTTP (No SSL/TLS encryption). Data transmitted can be intercepted or manipulated.",
                {"scheme": normalized.scheme},
            )
        )
        if features["has_ip"] or any(keyword in decoded_path for keyword in ("login", "signin", "verify", "auth", "account")):
            signals.append(
                make_signal(
                    "http_with_sensitive_context",
                    "high",
                    RISK_WEIGHTS["http_with_sensitive_context"],
                    "Insecure HTTP connection used for sensitive login, credential, or authentication endpoint.",
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


def _brand_references_in_path_or_query(normalized, decoded_path_query):
    references = []
    for brand in TRUSTED_BRANDS:
        official_domain = brand["domain"].lower()
        if normalized.registrable_domain == official_domain or normalized.hostname.endswith(f".{official_domain}"):
            continue
        if official_domain in decoded_path_query or f"www.{official_domain}" in decoded_path_query:
            references.append(
                {
                    "brand": brand["brand"],
                    "official_domain": official_domain,
                    "actual_domain": normalized.registrable_domain,
                }
            )
    return references


def _has_platform_tracking_shape(normalized, features):
    keys = {key.lower() for key, _ in normalized.query_parameters}
    tracking_keys = {"id", "u", "utm_campaign", "utm_medium", "utm_source", "web", "email"}
    return (
        features["query_param_count"] >= 2
        or bool(keys.intersection(tracking_keys))
        or features["opaque_path_token_count"] > 0
        or features["longest_path_segment"] >= 18
    )


def _has_sensitive_platform_language(decoded_host, decoded_path_query):
    sensitive_terms = {
        "account",
        "auth",
        "bank",
        "card",
        "checkout",
        "credential",
        "identifier",
        "login",
        "mail",
        "pay",
        "secure",
        "signin",
        "verify",
        "wallet",
        "webmail",
    }
    haystack = f"{decoded_host} {decoded_path_query}"
    return any(term in haystack for term in sensitive_terms)
