from urllib.parse import unquote

from .config import RISK_WEIGHTS
from .signals import make_signal
from .url_utils import get_registrable_domain


def analyze_adversarial(normalized, features, trusted_domains):
    findings = []
    signals = []

    if normalized.username:
        deceptive_domain = _userinfo_domain_candidate(normalized.username)
        finding = {
            "technique": "at_symbol_deception",
            "severity": "critical",
            "actual_domain": normalized.registrable_domain,
            "actual_hostname": normalized.hostname,
            "deceptive_domain": deceptive_domain or normalized.username,
            "reason": "Content before @ is user information; the hostname after @ is the actual destination.",
        }
        if deceptive_domain and deceptive_domain in trusted_domains and deceptive_domain != normalized.registrable_domain:
            finding["reason"] = "Trusted-looking domain appears before @ but is not the actual destination."
        findings.append(finding)
        score = (
            RISK_WEIGHTS["at_symbol_deception"]
            if deceptive_domain and deceptive_domain in trusted_domains and deceptive_domain != normalized.registrable_domain
            else RISK_WEIGHTS["userinfo_in_url"]
        )
        severity = "critical" if score >= RISK_WEIGHTS["at_symbol_deception"] else "high"
        signals.append(
            make_signal(
                "at_symbol_deception",
                severity,
                score,
                finding["reason"],
                {
                    "actual_domain": normalized.registrable_domain,
                    "deceptive_domain": finding["deceptive_domain"],
                },
            )
        )

    if features["has_ip"]:
        finding = {
            "technique": "ip_based_destination",
            "severity": "medium",
            "ip_address": normalized.ip_address,
            "actual_domain": normalized.ip_address,
            "reason": "URL uses an IPv4 address instead of a named domain.",
        }
        findings.append(finding)
        signals.append(
            make_signal(
                "ip_based_url",
                "medium",
                RISK_WEIGHTS["ip_based_url"],
                finding["reason"],
                {"ip_address": normalized.ip_address},
            )
        )

    return signals, findings


def _userinfo_domain_candidate(username):
    decoded = unquote(username).lower().strip()
    if not decoded or "." not in decoded:
        return None
    candidate = decoded.split("/")[-1].strip(".")
    return get_registrable_domain(candidate)
