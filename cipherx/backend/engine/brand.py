import re

from .config import RISK_WEIGHTS, TRUSTED_BRANDS
from .signals import make_signal
from .url_utils import get_registrable_domain


LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})


def analyze_brand(normalized, features):
    analyzed_domain = normalized.registrable_domain
    analyzed_root = _root_label(analyzed_domain)
    host_tokens = _tokens(normalized.hostname)
    subdomain = normalized.subdomain
    results = []
    signals = []

    for reference in TRUSTED_BRANDS:
        official_domain = reference["domain"]
        official_root = _root_label(official_domain)
        official_match = analyzed_domain == official_domain or normalized.hostname.endswith(f".{official_domain}")
        domain_similarity = _best_similarity(analyzed_root, official_root)
        token_similarity = max((_best_similarity(token, official_root) for token in host_tokens), default=0.0)
        brand_embedded_in_domain = (
            official_root in analyzed_root
            and analyzed_root != official_root
            and len(official_root) >= 5
        )
        brand_in_subdomain = bool(subdomain) and _contains_domain_sequence(subdomain, official_domain)
        brand_embedded_in_subdomain = (
            bool(subdomain)
            and not official_match
            and any(
                official_root in token
                and token != official_root
                for token in _tokens(subdomain)
            )
        )
        similarity = max(domain_similarity, token_similarity)

        result = {
            "detected_brand": reference["brand"],
            "analyzed_domain": analyzed_domain,
            "official_domain": official_domain,
            "similarity_score": round(similarity, 3),
            "official_domain_matches": official_match,
            "brand_in_subdomain": brand_in_subdomain,
            "brand_embedded_in_domain": brand_embedded_in_domain,
            "brand_embedded_in_subdomain": brand_embedded_in_subdomain,
            "supporting_evidence": [],
        }

        if official_match:
            result["supporting_evidence"].append("Hostname is on the official domain or a subdomain of it.")
        elif brand_in_subdomain:
            result["supporting_evidence"].append("Official-looking brand domain appears only inside the subdomain.")
            signals.append(
                make_signal(
                    "brand_subdomain_deception",
                    "high",
                    RISK_WEIGHTS["brand_subdomain_deception"],
                    "Trusted-looking brand domain appears in the subdomain, not the actual registrable domain.",
                    {
                        "brand": reference["brand"],
                        "official_domain": official_domain,
                        "analyzed_domain": analyzed_domain,
                        "subdomain": subdomain,
                    },
                )
            )
        elif similarity >= 0.86:
            result["supporting_evidence"].append("Analyzed domain is highly similar to a trusted brand reference.")
            signals.append(
                make_signal(
                    "brand_typosquatting",
                    "high",
                    RISK_WEIGHTS["brand_typosquatting"],
                    "Domain closely resembles a trusted brand but does not match the official domain.",
                    {
                        "brand": reference["brand"],
                        "official_domain": official_domain,
                        "analyzed_domain": analyzed_domain,
                        "similarity": round(similarity, 3),
                    },
                )
            )
        elif (brand_embedded_in_domain or brand_embedded_in_subdomain) and (
            features["suspicious_tld"]
            or features["num_hyphens"] > 0
            or features["num_digits"] > 0
        ):
            result["supporting_evidence"].append(
                "Trusted brand name is embedded in an unrelated domain with suspicious URL traits."
            )
            signals.append(
                make_signal(
                    "brand_name_in_untrusted_domain",
                    "high",
                    RISK_WEIGHTS["brand_name_in_untrusted_domain"],
                    "A trusted brand name appears inside an unrelated hostname with suspicious URL traits.",
                    {
                        "brand": reference["brand"],
                        "official_domain": official_domain,
                        "analyzed_domain": analyzed_domain,
                    },
                )
            )
        elif similarity >= 0.72 and (
            features["suspicious_tld"] or features["suspicious_keywords"] or features["num_hyphens"] > 0
        ):
            result["supporting_evidence"].append(
                "Domain has partial brand similarity combined with other suspicious URL traits."
            )
            signals.append(
                make_signal(
                    "brand_domain_mismatch",
                    "medium",
                    RISK_WEIGHTS["brand_domain_mismatch"],
                    "Domain partially resembles a trusted brand and also has supporting suspicious traits.",
                    {
                        "brand": reference["brand"],
                        "official_domain": official_domain,
                        "analyzed_domain": analyzed_domain,
                        "similarity": round(similarity, 3),
                    },
                )
            )

        if result["supporting_evidence"] or similarity >= 0.65:
            results.append(result)

    best = _best_result(results)
    return signals, {
        "analyzed_domain": analyzed_domain,
        "best_match": best,
        "matches": sorted(results, key=lambda item: item["similarity_score"], reverse=True)[:5],
        "impersonated_brand": None if not best or best["official_domain_matches"] else best["detected_brand"],
        "similarity_score": 0.0 if not best else best["similarity_score"],
    }


def trusted_domain_set():
    return {brand["domain"] for brand in TRUSTED_BRANDS}


def _root_label(domain):
    return domain.split(".")[0].lower()


def _tokens(hostname):
    raw_tokens = re.split(r"[^a-zA-Z0-9]+", hostname.lower())
    tokens = []
    for token in raw_tokens:
        if token:
            tokens.append(token)
            tokens.append(token.translate(LEET_MAP))
    return tokens


def _best_similarity(value, reference):
    candidates = {value, value.translate(LEET_MAP)}
    candidates.update(_tokens(value))
    return max((_similarity(candidate, reference) for candidate in candidates if candidate), default=0.0)


def _similarity(left, right):
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    distance = _levenshtein(left, right)
    return 1 - (distance / max(len(left), len(right)))


def _levenshtein(left, right):
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def _contains_domain_sequence(subdomain, official_domain):
    labels = [label for label in subdomain.lower().split(".") if label]
    if len(labels) < 2:
        return False
    domain_labels = official_domain.lower().split(".")
    if len(domain_labels) < 2:
        return False
    window = len(domain_labels)
    for index in range(0, len(labels) - window + 1):
        if labels[index : index + window] == domain_labels:
            return True
    return False


def _best_result(results):
    if not results:
        return None
    return sorted(
        results,
        key=lambda item: (
            item["official_domain_matches"],
            item["brand_in_subdomain"],
            item["similarity_score"],
        ),
        reverse=True,
    )[0]
