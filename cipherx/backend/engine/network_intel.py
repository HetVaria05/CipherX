import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .url_utils import get_registrable_domain, normalize_url


NETWORK_TIMEOUT_SECONDS = 5


def collect_network_intel(normalized, include_redirects: bool = True) -> dict:
    safety = evaluate_network_safety(normalized.hostname)
    dns = collect_dns_intel(normalized.hostname, normalized.registrable_domain)

    result = {
        "safety": safety,
        "dns": dns,
        "tls_certificate": collect_tls_certificate(normalized.hostname) if safety["safe_for_network_probe"] else _blocked("TLS probe blocked by host safety policy."),
        "whois_rdap": collect_rdap_domain(normalized.registrable_domain) if safety["safe_for_network_probe"] else _blocked("RDAP lookup blocked by host safety policy."),
        "redirect_chain": [],
        "content_scan": {
            "status": "not_fetched",
            "summary": "CipherX advanced scan does not download page bodies; use reputation, redirect, DNS, TLS, and RDAP metadata instead.",
        },
    }

    if include_redirects:
        result["redirect_chain"] = collect_redirect_chain(normalized.normalized_url)

    return result


def evaluate_network_safety(hostname: str) -> dict:
    blocked_reasons = []
    if not hostname:
        blocked_reasons.append("missing_hostname")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        blocked_reasons.append("localhost_hostname")

    addresses = _socket_addresses(hostname)
    unsafe_addresses = [address for address in addresses if _unsafe_ip(address)]
    if unsafe_addresses:
        blocked_reasons.append("private_or_reserved_address")

    return {
        "safe_for_network_probe": not blocked_reasons,
        "blocked_reasons": blocked_reasons,
        "resolved_addresses": addresses,
        "unsafe_addresses": unsafe_addresses,
    }


def collect_dns_intel(hostname: str, registrable_domain: str) -> dict:
    result = {
        "status": "ok",
        "hostname": hostname,
        "addresses": _socket_addresses(hostname),
        "a_records": [],
        "aaaa_records": [],
        "ns_records": [],
        "mx_records": [],
        "minimum_ttl": None,
        "summary": None,
    }

    try:
        import dns.resolver
    except Exception:
        result["status"] = "partial"
        result["summary"] = "Install dnspython to include DNS TTL, NS, MX, A, and AAAA record metadata."
        return result

    for record_type, key, target in (
        ("A", "a_records", hostname),
        ("AAAA", "aaaa_records", hostname),
        ("NS", "ns_records", registrable_domain),
        ("MX", "mx_records", registrable_domain),
    ):
        try:
            answer = dns.resolver.resolve(target, record_type, lifetime=NETWORK_TIMEOUT_SECONDS)
            ttl = getattr(answer.rrset, "ttl", None)
            if ttl is not None:
                result["minimum_ttl"] = ttl if result["minimum_ttl"] is None else min(result["minimum_ttl"], ttl)
            result[key] = [str(item).rstrip(".") for item in answer]
        except Exception:
            continue

    result["summary"] = _dns_summary(result)
    return result


def collect_tls_certificate(hostname: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=NETWORK_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception as err:
        return {"status": "error", "summary": "TLS certificate probe failed.", "error": str(err)}

    not_before = _parse_cert_date(cert.get("notBefore"))
    not_after = _parse_cert_date(cert.get("notAfter"))
    now = datetime.now(timezone.utc)
    expires_in_days = (not_after - now).days if not_after else None
    age_days = (now - not_before).days if not_before else None
    issuer = _cert_name(cert.get("issuer", ()))
    subject = _cert_name(cert.get("subject", ()))

    return {
        "status": "ok",
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "age_days": age_days,
        "expires_in_days": expires_in_days,
        "summary": _tls_summary(age_days, expires_in_days, issuer),
    }


def collect_rdap_domain(registrable_domain: str) -> dict:
    if not registrable_domain or _looks_like_ip(registrable_domain):
        return {"status": "skipped", "summary": "RDAP domain lookup skipped for IP-based URL."}

    request = urllib.request.Request(
        f"https://rdap.org/domain/{urllib.parse.quote(registrable_domain)}",
        headers={"accept": "application/rdap+json, application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return {"status": "not_found" if err.code == 404 else "error", "summary": "RDAP lookup failed.", "http_status": err.code}
    except Exception as err:
        return {"status": "error", "summary": "RDAP lookup failed.", "error": str(err)}

    events = payload.get("events", []) or []
    registration = _event_date(events, {"registration"})
    expiration = _event_date(events, {"expiration"})
    last_changed = _event_date(events, {"last changed", "last update of rdap database"})
    now = datetime.now(timezone.utc)
    age_days = (now - registration).days if registration else None
    expires_in_days = (expiration - now).days if expiration else None

    return {
        "status": "ok",
        "domain": registrable_domain,
        "handle": payload.get("handle"),
        "registration_date": registration.isoformat() if registration else None,
        "expiration_date": expiration.isoformat() if expiration else None,
        "last_changed": last_changed.isoformat() if last_changed else None,
        "age_days": age_days,
        "expires_in_days": expires_in_days,
        "nameservers": [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")],
        "registrar": _registrar(payload),
        "summary": _rdap_summary(age_days, expires_in_days),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def collect_redirect_chain(url: str, max_redirects: int = 5) -> list[dict]:
    chain = []
    current = url
    opener = urllib.request.build_opener(_NoRedirect)

    for index in range(max_redirects + 1):
        try:
            normalized = normalize_url(current)
        except ValueError as err:
            chain.append({"url": current, "status": "invalid_url", "error": str(err)})
            break

        safety = evaluate_network_safety(normalized.hostname)
        if not safety["safe_for_network_probe"]:
            chain.append(
                {
                    "url": current,
                    "hostname": normalized.hostname,
                    "status": "blocked",
                    "blocked_reasons": safety["blocked_reasons"],
                }
            )
            break

        request = urllib.request.Request(
            current,
            headers={"user-agent": "CipherX-Advanced-Scanner/1.0"},
            method="HEAD",
        )

        try:
            response = opener.open(request, timeout=NETWORK_TIMEOUT_SECONDS)
            status_code = response.getcode()
            headers = response.headers
            response.close()
        except urllib.error.HTTPError as err:
            status_code = err.code
            headers = err.headers
        except Exception as err:
            chain.append({"url": current, "hostname": normalized.hostname, "status": "error", "error": str(err)})
            break

        location = headers.get("Location") if headers else None
        next_url = urllib.parse.urljoin(current, location) if location else None
        entry = {
            "url": current,
            "hostname": normalized.hostname,
            "registrable_domain": normalized.registrable_domain,
            "status": "redirect" if next_url and 300 <= status_code < 400 else "final",
            "status_code": status_code,
            "location": next_url,
            "cross_domain": False,
        }
        if next_url:
            try:
                next_normalized = normalize_url(next_url)
                entry["cross_domain"] = next_normalized.registrable_domain != normalized.registrable_domain
            except ValueError:
                entry["cross_domain"] = True
        chain.append(entry)

        if not next_url or not (300 <= status_code < 400):
            break
        current = next_url

        if index == max_redirects:
            chain.append({"url": current, "status": "max_redirects_reached"})

    return chain


def _socket_addresses(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return []
    return sorted({info[4][0] for info in infos})


def _unsafe_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def _blocked(summary: str) -> dict:
    return {"status": "blocked", "summary": summary}


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_cert_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _cert_name(parts) -> dict:
    flattened = {}
    for group in parts:
        for key, value in group:
            flattened[key] = value
    return flattened


def _event_date(events: list[dict], names: set[str]):
    for event in events:
        action = str(event.get("eventAction", "")).lower()
        if action not in names:
            continue
        value = event.get("eventDate")
        if not value:
            continue
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def _registrar(payload: dict) -> str | None:
    for entity in payload.get("entities", []) or []:
        roles = {role.lower() for role in entity.get("roles", [])}
        if "registrar" in roles:
            return entity.get("vcardArray", [None, []])[1][1][3] if len(entity.get("vcardArray", [None, []])[1]) > 1 else entity.get("handle")
    return None


def _dns_summary(result: dict) -> str:
    if result.get("minimum_ttl") is not None and result["minimum_ttl"] <= 300:
        return "Domain has a low DNS TTL, which can indicate fast-changing infrastructure."
    if result.get("addresses"):
        return "DNS resolved successfully."
    return "No DNS address records were resolved."


def _tls_summary(age_days: int | None, expires_in_days: int | None, issuer: dict) -> str:
    if expires_in_days is not None and expires_in_days < 0:
        return "TLS certificate is expired."
    if age_days is not None and age_days <= 14:
        return "TLS certificate is very new."
    issuer_name = issuer.get("organizationName") or issuer.get("commonName")
    return f"TLS certificate is present{f' from {issuer_name}' if issuer_name else ''}."


def _rdap_summary(age_days: int | None, expires_in_days: int | None) -> str:
    if age_days is not None and age_days <= 30:
        return "Domain registration appears very recent."
    if expires_in_days is not None and expires_in_days <= 30:
        return "Domain registration expires soon."
    if age_days is not None:
        return "Domain registration age is available from RDAP."
    return "RDAP record found, but registration date was not available."
