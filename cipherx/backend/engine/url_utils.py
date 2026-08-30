import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

try:
    import tldextract
    _tld_extractor = tldextract.TLDExtract(cache_dir=None)
except Exception:
    _tld_extractor = None

ALLOWED_SCHEMES = {"http", "https"}

MULTI_PART_SUFFIXES = {
    "ac.in",
    "co.in",
    "com.au",
    "co.uk",
    "co.jp",
    "edu.in",
    "gov.in",
    "net.in",
    "org.uk",
}


@dataclass(frozen=True)
class NormalizedURL:
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int | None
    username: str | None
    password: str | None
    path: str
    query: str
    fragment: str
    query_parameters: list[tuple[str, str]]
    registrable_domain: str
    subdomain: str
    tld: str
    is_ipv4: bool
    ip_address: str | None
    had_missing_scheme: bool


def normalize_url(raw_url: str) -> NormalizedURL:
    original = raw_url.strip()
    if not original:
        raise ValueError("URL cannot be empty")

    initial_parsed = urlsplit(original)
    if initial_parsed.scheme:
        if initial_parsed.scheme.lower() not in ALLOWED_SCHEMES:
            raise ValueError("Only http/https URLs are allowed")
        parse_target = original
        had_missing_scheme = False
    else:
        parse_target = f"https:{original}" if original.startswith("//") else f"https://{original}"
        had_missing_scheme = True

    parsed = urlsplit(parse_target)
    scheme = (parsed.scheme or "https").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only http/https URLs are allowed")

    if not parsed.hostname:
        raise ValueError("URL must include a hostname")


    hostname = parsed.hostname.rstrip(".").lower()
    port = _safe_port(parsed)
    username = parsed.username
    password = parsed.password
    path = _normalize_percent_encoding(parsed.path or "/")
    query = _normalize_percent_encoding(parsed.query or "")
    fragment = _normalize_percent_encoding(parsed.fragment or "")
    is_ip, ip_address, is_ipv4 = _ip_details(hostname)
    registrable_domain = get_registrable_domain(hostname)
    subdomain = get_subdomain(hostname, registrable_domain)
    tld = get_tld(hostname)

    # Format netloc properly for IPv6 literals vs standard hostnames
    if is_ip and not is_ipv4 and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    else:
        netloc = hostname

    if port is not None:
        netloc = f"{netloc}:{port}"

    # Drop fragment from normalized_url for consistent server-side caching & scanning
    normalized = urlunsplit((scheme, netloc, path or "/", query, ""))


    return NormalizedURL(
        original_url=original,
        normalized_url=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        username=username,
        password=password,
        path=path or "/",
        query=query,
        fragment=fragment,
        query_parameters=parse_qsl(query, keep_blank_values=True),
        registrable_domain=registrable_domain,
        subdomain=subdomain,
        tld=tld,
        is_ipv4=is_ipv4,
        ip_address=ip_address,
        had_missing_scheme=had_missing_scheme,
    )


def get_registrable_domain(hostname: str) -> str:
    is_ip, _, _ = _ip_details(hostname)
    if is_ip:
        return hostname

    if _tld_extractor:
        try:
            extracted = _tld_extractor(hostname)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
            if extracted.domain:
                return extracted.domain
        except Exception:
            pass

    labels = [label for label in hostname.rstrip(".").lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)

    suffix = ".".join(labels[-2:])
    if suffix in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def get_subdomain(hostname: str, registrable_domain: str) -> str:
    is_ip, _, _ = _ip_details(hostname)
    if is_ip or not registrable_domain:
        return ""

    if _tld_extractor:
        try:
            extracted = _tld_extractor(hostname)
            return extracted.subdomain
        except Exception:
            pass

    suffix = f".{registrable_domain}"
    return hostname[: -len(suffix)] if hostname.endswith(suffix) else ""


def get_tld(hostname: str) -> str:
    is_ip, _, _ = _ip_details(hostname)
    if is_ip:
        return ""

    if _tld_extractor:
        try:
            extracted = _tld_extractor(hostname)
            return extracted.suffix
        except Exception:
            pass

    labels = [label for label in hostname.lower().split(".") if label]
    if len(labels) >= 2 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-2:])
    return labels[-1] if labels else ""


def _safe_port(parsed) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def _ip_details(hostname: str) -> tuple[bool, str | None, bool]:
    """
    Checks if hostname is an IPv4 or IPv6 address.
    Returns: (is_ip, ip_str, is_ipv4)
    """
    cleaned_hostname = hostname.strip("[]")
    try:
        ip = ipaddress.ip_address(cleaned_hostname)
        return True, str(ip), isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False, None, False


def _normalize_percent_encoding(value: str) -> str:
    return re.sub(
        r"%[0-9a-fA-F]{2}",
        lambda match: match.group(0).upper(),
        value,
    )

