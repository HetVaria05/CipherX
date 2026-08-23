import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit


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

    had_missing_scheme = not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original)
    parse_target = original
    if had_missing_scheme:
        parse_target = f"https:{original}" if original.startswith("//") else f"https://{original}"

    parsed = urlsplit(parse_target)
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")

    scheme = (parsed.scheme or "https").lower()
    hostname = parsed.hostname.rstrip(".").lower()
    port = _safe_port(parsed)
    username = parsed.username
    password = parsed.password
    path = _normalize_percent_encoding(parsed.path or "")
    query = _normalize_percent_encoding(parsed.query or "")
    fragment = _normalize_percent_encoding(parsed.fragment or "")
    is_ipv4, ip_address = _ipv4_details(hostname)
    registrable_domain = get_registrable_domain(hostname)
    subdomain = get_subdomain(hostname, registrable_domain)
    tld = get_tld(hostname)

    netloc = hostname
    if username is not None:
        userinfo = quote(username, safe="")
        if password is not None:
            userinfo = f"{userinfo}:{quote(password, safe='')}"
        netloc = f"{userinfo}@{netloc}"
    if port is not None:
        netloc = f"{netloc}:{port}"

    normalized = urlunsplit((scheme, netloc, path or "/", query, fragment))

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
    if _ipv4_details(hostname)[0]:
        return hostname

    labels = [label for label in hostname.rstrip(".").lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)

    suffix = ".".join(labels[-2:])
    if suffix in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def get_subdomain(hostname: str, registrable_domain: str) -> str:
    if not registrable_domain or hostname == registrable_domain:
        return ""
    suffix = f".{registrable_domain}"
    return hostname[: -len(suffix)] if hostname.endswith(suffix) else ""


def get_tld(hostname: str) -> str:
    if _ipv4_details(hostname)[0]:
        return ""
    labels = [label for label in hostname.lower().split(".") if label]
    if len(labels) >= 2 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-2:])
    return labels[-1] if labels else ""


def _safe_port(parsed) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def _ipv4_details(hostname: str) -> tuple[bool, str | None]:
    try:
        ip = ipaddress.IPv4Address(hostname)
    except ValueError:
        return False, None
    return True, str(ip)


def _normalize_percent_encoding(value: str) -> str:
    return re.sub(
        r"%[0-9a-fA-F]{2}",
        lambda match: match.group(0).upper(),
        value,
    )
