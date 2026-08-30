import json
import os
import logging
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
from .signals import make_signal

logger = logging.getLogger(__name__)

# Curated high-reputation domain whitelist (Top 100+ global & regional services)
GLOBAL_TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com",
    "microsoft.com", "live.com", "office.com", "azure.com", "github.com",
    "apple.com", "icloud.com", "amazon.com", "amazon.in", "aws.amazon.com",
    "netflix.com", "twitter.com", "x.com", "linkedin.com", "wikipedia.org",
    "cloudflare.com", "yahoo.com", "bing.com", "spotify.com", "reddit.com",
    "paypal.com", "stripe.com", "paytm.com", "phonepe.com", "razorpay.com",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com",
    "gov.in", "india.gov.in", "uidai.gov.in", "incometax.gov.in", "cybercrime.gov.in",
    "virustotal.com", "abuse.ch", "phishtank.com", "shodan.io"
}

# Curated seed database of known active malicious hostnames / URL patterns
KNOWN_MALICIOUS_DOMAINS = {
    "suspicious-bank-login.xyz": {"threat": "Phishing", "family": "CredentialHarvester", "source": "PhishTank"},
    "secure-verify-paypal.com.tk": {"threat": "Phishing", "family": "FinancialScam", "source": "OpenPhish"},
    "update-account-kyc-alert.top": {"threat": "Phishing", "family": "SmishingTarget", "source": "CyberCrimeFeed"},
    "free-crypto-giveaway-airdrop.xyz": {"threat": "Scam/Drainer", "family": "CryptoDrainer", "source": "URLhaus"},
    "apple-id-suspended-recovery.link": {"threat": "Phishing", "family": "ApplePhish", "source": "PhishTank"},
    "sbi-reward-points-redeem.click": {"threat": "Phishing", "family": "BankingTrojan", "source": "CERT-In Feed"},
    "netflix-billing-update-failed.info": {"threat": "Phishing", "family": "SubscriptionScam", "source": "OpenPhish"},
    "whatsapp-gold-installer.ru": {"threat": "Malware", "family": "SpywareDropper", "source": "URLhaus"},
    "metamask-wallet-synchronize.pw": {"threat": "Phishing", "family": "SeedPhraseTheft", "source": "ThreatFox"},
    "parcel-delivery-tracking-failed.support": {"threat": "Phishing", "family": "DeliveryScam", "source": "URLhaus"},
    "https://github.com/pistacchietto/win-python-backdoor/raw/master/win.bat": {"threat": "Malware", "family": "ScriptDropper", "source": "URLhaus"},
}

# Try to load the large dataset
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_file = os.path.join(os.path.dirname(current_dir), "data", "malicious_feed.json")
    if os.path.exists(data_file):
        with open(data_file, 'r', encoding='utf-8') as f:
            large_dataset = json.load(f)
            KNOWN_MALICIOUS_DOMAINS.update({key.lower(): value for key, value in large_dataset.items()})
            logger.info(f"Loaded {len(large_dataset)} IOCs from local dataset.")
except Exception as e:
    logger.error(f"Could not load malicious feed dataset: {e}")



def is_globally_trusted(domain: str) -> bool:
    """Check if the domain is in our verified top global whitelist."""
    if not domain:
        return False
    domain_lower = domain.lower()
    return (
        domain_lower in GLOBAL_TRUSTED_DOMAINS
        or any(domain_lower.endswith("." + trusted) for trusted in GLOBAL_TRUSTED_DOMAINS)
    )


def query_urlhaus_api(url: str, timeout: float = 1.2) -> Optional[Dict[str, Any]]:
    """
    Queries abuse.ch URLhaus real-time threat intelligence API.
    Zero-authentication needed; fails fast if offline or timeout.
    """
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        data = urllib.parse.urlencode({"url": url}).encode("utf-8")
        req = urllib.request.Request(
            api_url,
            data=data,
            headers={"User-Agent": "CipherX-Threat-Intel/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                result = json.loads(response.read().decode("utf-8"))
                if result.get("query_status") == "ok":
                    return {
                        "source": "URLhaus (abuse.ch)",
                        "threat_type": result.get("threat", "Malware"),
                        "url_status": result.get("url_status", "active"),
                        "tags": result.get("tags") or [],
                        "date_added": result.get("date_added"),
                        "threat_actor": result.get("reporter", "abuse.ch Community"),
                    }
    except Exception as err:
        logger.debug(f"URLhaus live query bypassed ({err})")
    return None


def lookup_threat_intel(normalized_url: str, hostname: str, domain: str) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Performs multi-layered threat intelligence database lookups:
    1. Local High-Confidence Threat Feed
    2. Real-Time URLhaus IOC API Feed
    """
    signals = []
    intel_match = None

    # 1. Check Local Known Malicious Dataset
    matched_entry, matched_indicator = _match_local_ioc(normalized_url, hostname, domain)
    if matched_entry:
        threat = matched_entry.get("threat", "Malicious URL")
        family = matched_entry.get("family", "Unknown")
        source = matched_entry.get("source", "Local Threat Feed")
        intel_match = {
            "source": source,
            "threat_type": threat,
            "family": family,
            "indicator": matched_indicator,
            "status": "active_threat",
            "confidence": 0.99,
        }
        signals.append(
            make_signal(
                "threat_intel_ioc_match",
                "critical",
                100,
                f"Verified threat indicator in {source} database ({threat} / {family}).",
                intel_match
            )
        )
        return signals, intel_match

    # 2. Query Live URLhaus API
    live_match = query_urlhaus_api(normalized_url)
    if live_match:
        intel_match = live_match
        tags_str = ", ".join(live_match.get("tags", [])) or "Malicious"
        signals.append(
            make_signal(
                "urlhaus_threat_match",
                "critical",
                100,
                f"Live match in abuse.ch URLhaus threat feed (Threat: {live_match['threat_type']}, Tags: {tags_str}).",
                live_match
            )
        )
        return signals, intel_match

    return signals, None


def _match_local_ioc(normalized_url: str, hostname: str, domain: str):
    for indicator in _local_ioc_candidates(normalized_url, hostname, domain):
        match = KNOWN_MALICIOUS_DOMAINS.get(indicator)
        if match:
            return match, indicator
    return None, None


def _local_ioc_candidates(normalized_url: str, hostname: str, domain: str):
    lowered_url = normalized_url.lower()
    decoded_url = urllib.parse.unquote(lowered_url)
    candidates = [
        lowered_url,
        lowered_url.rstrip("/"),
        decoded_url,
        decoded_url.rstrip("/"),
    ]

    # Only include naked host/domain candidates if they are NOT in the verified global trusted domains
    if not is_globally_trusted(hostname):
        candidates.append(hostname.lower())
        if hostname.lower().startswith("www."):
            candidates.append(hostname.lower()[4:])

    if not is_globally_trusted(domain):
        candidates.append(domain.lower())

    deduped = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped

