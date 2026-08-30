import asyncio
import ipaddress
import json
import logging
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    httpx = None

from .url_utils import normalize_url

logger = logging.getLogger(__name__)

NETWORK_TIMEOUT_SECONDS = 5
CONTENT_FETCH_TIMEOUT_SECONDS = 4
MAX_CONTENT_BYTES = 65536
CONTENT_SUSPICIOUS_TERMS = {
    "account",
    "auth",
    "bank",
    "credential",
    "login",
    "payment",
    "password",
    "recovery",
    "signin",
    "security",
    "verification",
    "verify",
    "wallet",
}


def collect_network_intel(normalized, include_redirects: bool = True) -> dict:
    safety = evaluate_network_safety(normalized.hostname)
    dns = collect_dns_intel(normalized.hostname, normalized.registrable_domain)
    content_scan = (
        collect_content_scan(normalized)
        if safety["safe_for_network_probe"]
        else _blocked("Content probe blocked by host safety policy.")
    )

    result = {
        "safety": safety,
        "dns": dns,
        "tls_certificate": (
            collect_tls_certificate(normalized.hostname)
            if safety["safe_for_network_probe"]
            else _blocked("TLS probe blocked by host safety policy.")
        ),
        "whois_rdap": (
            collect_rdap_domain(normalized.registrable_domain)
            if safety["safe_for_network_probe"]
            else _blocked("RDAP lookup blocked by host safety policy.")
        ),
        "redirect_chain": [],
        "content_scan": content_scan,
    }

    if include_redirects and safety["safe_for_network_probe"]:
        result["redirect_chain"] = collect_redirect_chain(normalized.normalized_url)
    elif include_redirects:
        result["redirect_chain"] = [
            {
                "url": normalized.normalized_url,
                "hostname": normalized.hostname,
                "status": "blocked",
                "blocked_reasons": safety["blocked_reasons"],
            }
        ]

    return result


async def collect_network_intel_async(normalized, include_redirects: bool = True) -> dict:
    return await asyncio.to_thread(collect_network_intel, normalized, include_redirects)


def collect_content_scan(normalized) -> dict:
    sample = _fetch_page_sample(normalized.normalized_url)
    if sample.get("status") != "ok":
        return sample

    parser = _ContentIntelParser()
    parser.feed(sample["body"])

    title = " ".join(part.strip() for part in parser.title_parts if part.strip()).strip()
    visible_text = " ".join(parser.visible_text).lower()
    form_actions = " ".join(parser.form_actions).lower()
    combined_text = f"{title.lower()} {visible_text} {form_actions}".strip()

    suspicious_terms = sorted(term for term in CONTENT_SUSPICIOUS_TERMS if term in combined_text)
    findings = []

    if parser.password_field_count and (parser.form_count or suspicious_terms):
        findings.append(
            {
                "signal": "credential_form_detected",
                "severity": "high",
                "score": 22,
                "reason": "Fetched page contains password fields or login form markers.",
                "details": {
                    "form_count": parser.form_count,
                    "password_field_count": parser.password_field_count,
                },
            }
        )

    if suspicious_terms:
        findings.append(
            {
                "signal": "credential_language_detected",
                "severity": "medium",
                "score": 12,
                "reason": "Fetched page contains credential, payment, or verification language.",
                "details": {"suspicious_terms": suspicious_terms},
            }
        )

    if parser.meta_refresh_count:
        findings.append(
            {
                "signal": "meta_refresh_redirect",
                "severity": "medium",
                "score": 10,
                "reason": "Fetched page uses a meta refresh redirect.",
                "details": {"meta_refresh_count": parser.meta_refresh_count},
            }
        )

    if parser.external_script_count >= 4:
        findings.append(
            {
                "signal": "heavy_external_script_surface",
                "severity": "low",
                "score": 6,
                "reason": "Fetched page loads several external scripts, which can hide dynamic phishing behavior.",
                "details": {"external_script_count": parser.external_script_count},
            }
        )

    summary = _content_summary(title, sample["content_type"], sample.get("truncated", False), findings)
    return {
        "status": "ok",
        "url": sample["url"],
        "content_type": sample["content_type"],
        "title": title or None,
        "form_count": parser.form_count,
        "password_field_count": parser.password_field_count,
        "external_script_count": parser.external_script_count,
        "inline_script_count": parser.inline_script_count,
        "meta_refresh_count": parser.meta_refresh_count,
        "truncated": sample.get("truncated", False),
        "findings": findings,
        "summary": summary,
    }


def evaluate_network_safety(hostname: str) -> dict:
    blocked_reasons = []
    if not hostname:
        return {
            "safe_for_network_probe": False,
            "blocked_reasons": ["missing_hostname"],
            "resolved_addresses": [],
            "unsafe_addresses": [],
        }

    cleaned_hostname = hostname.strip("[]").lower()
    if cleaned_hostname in {"localhost", "localhost.localdomain"} or cleaned_hostname.endswith(".localhost"):
        blocked_reasons.append("localhost_hostname")

    # If hostname is already a direct IP literal (v4 or v6), check directly
    if _looks_like_ip(cleaned_hostname):
        addresses = [cleaned_hostname]
        if _unsafe_ip(cleaned_hostname):
            blocked_reasons.append("private_or_reserved_address")
    else:
        addresses = _socket_addresses(cleaned_hostname)
        if not addresses:
            blocked_reasons.append("dns_resolution_failed")
        else:
            unsafe_addresses = [address for address in addresses if _unsafe_ip(address)]
            if unsafe_addresses:
                blocked_reasons.append("private_or_reserved_address")

    unsafe_addresses = [address for address in addresses if _unsafe_ip(address)]
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
                result["minimum_ttl"] = (
                    ttl if result["minimum_ttl"] is None else min(result["minimum_ttl"], ttl)
                )
            result[key] = [str(item).rstrip(".") for item in answer]
        except Exception:
            continue

    result["summary"] = _dns_summary(result)
    return result


def collect_tls_certificate(hostname: str) -> dict:
    safety = evaluate_network_safety(hostname)
    if not safety["safe_for_network_probe"]:
        return _blocked(f"TLS probe blocked: {', '.join(safety['blocked_reasons'])}")

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
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        with opener.open(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return {
            "status": "not_found" if err.code == 404 else "error",
            "summary": "RDAP lookup failed.",
            "http_status": err.code,
        }
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
        "nameservers": [
            item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")
        ],
        "registrar": _registrar(payload),
        "summary": _rdap_summary(age_days, expires_in_days),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def collect_redirect_chain(url: str, max_redirects: int = 5) -> list[dict]:
    chain = []
    current = url
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

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
            chain.append(
                {"url": current, "hostname": normalized.hostname, "status": "error", "error": str(err)}
            )
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
                # Ensure destination host safety is checked before proceeding
                next_safety = evaluate_network_safety(next_normalized.hostname)
                if not next_safety["safe_for_network_probe"]:
                    entry["next_safety_blocked"] = True
                    entry["blocked_reasons"] = next_safety["blocked_reasons"]
                entry["cross_domain"] = (
                    next_normalized.registrable_domain != normalized.registrable_domain
                )
            except ValueError:
                entry["cross_domain"] = True

        chain.append(entry)

        if not next_url or not (300 <= status_code < 400) or entry.get("next_safety_blocked"):
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
    return sorted({info[4][0] for info in infos if info and len(info) > 4 and info[4]})


def _unsafe_ip(address: str) -> bool:
    try:
        cleaned = address.strip("[]")
        ip = ipaddress.ip_address(cleaned)
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
        ipaddress.ip_address(value.strip("[]"))
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
            return (
                entity.get("vcardArray", [None, []])[1][1][3]
                if len(entity.get("vcardArray", [None, []])[1]) > 1
                else entity.get("handle")
            )
    return None


def _dns_summary(result: dict) -> str:
    if result.get("minimum_ttl") is not None and result["minimum_ttl"] <= 300:
        return "Domain has a low DNS TTL, which can indicate fast-changing infrastructure."
    if result.get("addresses"):
        return "DNS resolved successfully."
    return "No DNS address records were resolved."


def _content_summary(
    title: str | None, content_type: str | None, truncated: bool, findings: list[dict]
) -> str:
    prefix = f"{content_type or 'Content'} page fetched successfully"
    if title:
        prefix = f"{prefix} ({title})"
    if findings:
        return f"{prefix}; {len(findings)} suspicious content indicator(s) were found."
    if truncated:
        return f"{prefix}; sample truncated after the first 64 KB."
    return f"{prefix} with no obvious credential or redirect markers."


def _fetch_page_sample(url: str) -> dict:
    """
    Fetches sample with SSRF protection:
    1. Re-validates network safety of URL host
    2. Builds opener with _NoRedirect and empty ProxyHandler
    """
    try:
        normalized = normalize_url(url)
    except ValueError as err:
        return {"status": "error", "summary": "Invalid URL for content fetch.", "error": str(err)}

    safety = evaluate_network_safety(normalized.hostname)
    if not safety["safe_for_network_probe"]:
        return {
            "status": "blocked",
            "summary": f"Content fetch blocked by host safety policy: {', '.join(safety['blocked_reasons'])}",
        }

    request = urllib.request.Request(
        url,
        headers={
            "user-agent": "CipherX-Advanced-Scanner/1.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
        },
        method="GET",
    )

    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        with opener.open(request, timeout=CONTENT_FETCH_TIMEOUT_SECONDS) as response:
            content_type = (
                response.headers.get_content_type() if response.headers else "text/html"
            ) or "text/html"
            if content_type not in {"text/html", "application/xhtml+xml", "text/plain", "application/xml"}:
                return {
                    "status": "not_html",
                    "summary": f"Content type {content_type} not scanned.",
                    "content_type": content_type,
                }

            raw = response.read(MAX_CONTENT_BYTES + 1)
            truncated = len(raw) > MAX_CONTENT_BYTES
            payload = raw[:MAX_CONTENT_BYTES]
            charset = response.headers.get_content_charset() if response.headers else None
            body = payload.decode(charset or "utf-8", errors="replace")
            return {
                "status": "ok",
                "url": response.geturl() or url,
                "content_type": content_type,
                "body": body,
                "truncated": truncated,
            }
    except Exception as err:
        return {"status": "error", "summary": "Content fetch failed.", "error": str(err)}


class _ContentIntelParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title_parts = []
        self.visible_text = []
        self.form_actions = []
        self.form_count = 0
        self.password_field_count = 0
        self.external_script_count = 0
        self.inline_script_count = 0
        self.meta_refresh_count = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = {key.lower(): (value or "") for key, value in attrs}
        if tag == "title":
            self._in_title = True
            return
        if tag == "form":
            self.form_count += 1
            action = attrs.get("action")
            if action:
                self.form_actions.append(action)
            return
        if tag == "input" and attrs.get("type", "").lower() == "password":
            self.password_field_count += 1
            return
        if tag == "script":
            if attrs.get("src"):
                self.external_script_count += 1
            else:
                self.inline_script_count += 1
            return
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh_count += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return
        if self._in_title:
            self.title_parts.append(text)
        self.visible_text.append(text)


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

