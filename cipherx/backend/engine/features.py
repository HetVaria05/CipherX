import math
import re
import string
from urllib.parse import unquote

from .config import SUSPICIOUS_KEYWORDS, SUSPICIOUS_PORTS, SUSPICIOUS_TLDS


def extract_features(normalized):
    host = normalized.hostname
    domain = normalized.registrable_domain
    full_url = normalized.normalized_url
    letters = sum(1 for char in full_url if char.isalpha())
    digits = sum(1 for char in full_url if char.isdigit())
    encoded_sequences = re.findall(r"%[0-9A-Fa-f]{2}", normalized.original_url)
    decoded_url = unquote(normalized.normalized_url).lower()
    special_chars = [char for char in full_url if char in string.punctuation]
    suspicious_keywords = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in decoded_url
    )
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
