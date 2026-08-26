import math
import re
import string
from urllib.parse import unquote, urlsplit

from .config import (
    ABUSED_HOSTING_DOMAINS,
    ABUSED_MARKETING_FORM_DOMAINS,
    HIGH_RISK_FILE_EXTENSIONS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_PORTS,
    SUSPICIOUS_TLDS,
    URL_SHORTENER_DOMAINS,
)


def extract_features(normalized):
    host = normalized.hostname
    domain = normalized.registrable_domain
    full_url = normalized.normalized_url
    decoded_url = unquote(normalized.normalized_url).lower()
    decoded_path = unquote(normalized.path).lower()
    decoded_query = unquote(normalized.query).lower()
    decoded_fragment = unquote(normalized.fragment).lower()
    letters = sum(1 for char in full_url if char.isalpha())
    digits = sum(1 for char in full_url if char.isdigit())
    encoded_sequences = re.findall(r"%[0-9A-Fa-f]{2}", normalized.original_url)
    special_chars = [char for char in full_url if char in string.punctuation]
    suspicious_keywords = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in decoded_url
    )
    embedded_urls = _embedded_urls(f"{decoded_path}?{decoded_query}#{decoded_fragment}")
    embedded_domains = sorted(
        {
            candidate
            for candidate in (_embedded_domain(url) for url in embedded_urls)
            if candidate and not _same_site(candidate, host, domain)
        }
    )
    path_segments = [segment for segment in decoded_path.split("/") if segment]
    longest_path_segment = max((len(segment) for segment in path_segments), default=0)
    opaque_path_token_count = sum(1 for segment in path_segments if _is_opaque_token(segment))
    high_risk_file_extension = _high_risk_file_extension(decoded_path)
    normal_ports = {"http": 80, "https": 443}
    suspicious_port = (
        normalized.port is not None
        and normalized.port != normal_ports.get(normalized.scheme)
        and normalized.port in SUSPICIOUS_PORTS
    )

    entropy = shannon_entropy(domain.replace(".", "").replace("-", ""))

    return {
        "url_length": len(full_url),
        "hostname_length": len(host),
        "domain_length": len(domain),
        "subdomain_count": len([part for part in normalized.subdomain.split(".") if part]),
        "num_dots": host.count("."),
        "num_hyphens": full_url.count("-"),
        "num_digits": digits,
        "digit_letter_ratio": round(digits / letters, 3) if letters else 0,
        "path_length": len(normalized.path),
        "query_param_count": len(normalized.query_parameters),
        "special_character_count": len(special_chars),
        "has_at_symbol": normalized.username is not None,
        "has_ip": normalized.is_ipv4,
        "ip_address": normalized.ip_address,
        "uses_https": normalized.scheme == "https",
        "suspicious_port": suspicious_port,
        "port": normalized.port,
        "encoded_characters": len(encoded_sequences),
        "encoded_values": sorted(set(encoded.upper() for encoded in encoded_sequences)),
        "suspicious_keywords": suspicious_keywords,
        "embedded_urls": embedded_urls,
        "embedded_domains": embedded_domains,
        "is_url_shortener": _host_matches(host, domain, URL_SHORTENER_DOMAINS),
        "is_abused_hosting_platform": _host_matches(host, domain, ABUSED_HOSTING_DOMAINS),
        "is_marketing_or_form_platform": _host_matches(host, domain, ABUSED_MARKETING_FORM_DOMAINS),
        "path_segment_count": len(path_segments),
        "longest_path_segment": longest_path_segment,
        "opaque_path_token_count": opaque_path_token_count,
        "high_risk_file_extension": high_risk_file_extension,
        "has_high_risk_file_extension": high_risk_file_extension is not None,
        "domain_entropy": round(entropy, 3),
        "domain_complexity": round(_domain_complexity(domain, entropy), 3),
        "hostname": host,
        "registrable_domain": domain,
        "subdomain": normalized.subdomain,
        "tld": normalized.tld,
        "suspicious_tld": normalized.tld in SUSPICIOUS_TLDS,
        "has_username": normalized.username is not None,
        "has_password": normalized.password is not None,
        "had_missing_scheme": normalized.had_missing_scheme,
    }


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _domain_complexity(domain, entropy):
    compact = domain.replace(".", "")
    if not compact:
        return 0.0
    unique_ratio = len(set(compact)) / len(compact)
    digit_ratio = sum(1 for char in compact if char.isdigit()) / len(compact)
    hyphen_ratio = domain.count("-") / len(domain)
    return entropy + unique_ratio + digit_ratio + hyphen_ratio


def _host_matches(hostname, domain, candidates):
    return any(
        hostname == candidate
        or domain == candidate
        or hostname.endswith(f".{candidate}")
        for candidate in candidates
    )


def _same_site(candidate, hostname, domain):
    return (
        candidate == hostname
        or candidate == domain
        or candidate.endswith(f".{domain}")
    )


def _embedded_urls(decoded_url):
    matches = re.findall(r"(?:https?:/{1,2}|https?/{2}|www\.)[^\s\"'<>]+", decoded_url)
    cleaned = []
    for match in matches:
        candidate = match.rstrip(").,;]")
        if candidate and candidate not in cleaned:
            cleaned.append(candidate)
    return cleaned


def _embedded_domain(value):
    candidate = value
    if candidate.startswith("www."):
        candidate = f"https://{candidate}"
    candidate = candidate.replace("https//", "https://").replace("http//", "http://")
    parsed = urlsplit(candidate)
    if not parsed.hostname:
        return None
    return parsed.hostname.rstrip(".").lower()


def _is_opaque_token(segment):
    compact = re.sub(r"[^a-z0-9]", "", segment.lower())
    if len(compact) < 6:
        return False
    has_letters = any(char.isalpha() for char in compact)
    has_digits = any(char.isdigit() for char in compact)
    entropy = shannon_entropy(compact)
    # Mixed letter+digit tokens of length >= 6 (common in phishing campaigns e.g. egyw5fyj, v12k3j9, etc.)
    if has_letters and has_digits and len(compact) >= 6:
        return True
    # Pure letter tokens with low vowel count or high entropy
    if len(compact) >= 6:
        vowels = sum(1 for char in compact if char in "aeiou")
        if vowels == 0 or (len(compact) >= 7 and vowels <= 1):
            return True
        if entropy >= 2.8 and len(compact) >= 8:
            return True
    return False


def _high_risk_file_extension(path):
    lowered = path.split("?", 1)[0].lower()
    for extension in HIGH_RISK_FILE_EXTENSIONS:
        if lowered.endswith(extension):
            return extension
    return None
