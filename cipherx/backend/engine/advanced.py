import asyncio
import logging
from typing import Any, Dict, List, Optional

from .detector import analyze_url
from .network_intel import collect_network_intel, collect_network_intel_async
from .risk import classify
from .signals import make_signal
from .url_utils import normalize_url
from .virustotal import scan_url_report

logger = logging.getLogger(__name__)


async def advanced_analyze_url(
    url: str,
    virustotal_api_key: str | None = None,
    use_virustotal: bool = True,
    submit_to_virustotal: bool = False,
    include_network: bool = True,
) -> dict:
    # 1. Run base heuristic, ML & threat intel scan
    base_analysis = await analyze_url(url, include_network=False)
    normalized = normalize_url(base_analysis["normalized_url"])

    # 2. Concurrently fetch VirusTotal and Network Intel with graceful error handling
    vt_coro = (
        scan_url_report(base_analysis["normalized_url"], virustotal_api_key, submit_to_virustotal)
        if use_virustotal
        else None
    )
    net_coro = (
        collect_network_intel_async(normalized)
        if include_network
        else None
    )

    tasks = []
    task_keys = []
    if vt_coro:
        tasks.append(vt_coro)
        task_keys.append("virustotal")
    if net_coro:
        tasks.append(net_coro)
        task_keys.append("network")

    results_map = {}
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for key, res in zip(task_keys, results):
            if isinstance(res, Exception):
                logger.warning(f"Advanced scan sub-task {key} failed: {res}")
                results_map[key] = {
                    "status": "error",
                    "summary": f"{key.capitalize()} scan encountered a transient error.",
                    "error": str(res),
                }
            else:
                results_map[key] = res

    virustotal = results_map.get(
        "virustotal",
        (
            {"enabled": False, "status": "disabled", "summary": "VirusTotal lookup disabled for this request."}
            if not use_virustotal
            else {"status": "error", "summary": "VirusTotal lookup unavailable."}
        ),
    )

    network = results_map.get(
        "network",
        (
            {"status": "disabled", "summary": "Network enrichment disabled for this request."}
            if not include_network
            else {"status": "error", "summary": "Network intel unavailable."}
        ),
    )

    # 3. Aggregate advanced external signals
    advanced_signals = _advanced_signals(virustotal, network)
    all_signals = base_analysis["signals"] + advanced_signals
    risk_score = _combined_score(base_analysis["risk_score"], advanced_signals)
    classification = classify(risk_score)
    confidence = _advanced_confidence(base_analysis["confidence"], risk_score, advanced_signals)

    return {
        "url": base_analysis["url"],
        "normalized_url": base_analysis["normalized_url"],
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "signals": all_signals,
        "base_analysis": base_analysis,
        "advanced": {
            "virustotal": virustotal,
            "network": network,
            "signals": advanced_signals,
        },
        "explanation": _advanced_explanation(base_analysis, virustotal, advanced_signals, classification),
        "scan_duration_ms": base_analysis.get("scan_duration_ms"),
    }


def advanced_analyze_url_sync(
    url: str,
    virustotal_api_key: str | None = None,
    use_virustotal: bool = True,
    submit_to_virustotal: bool = False,
    include_network: bool = True,
) -> dict:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run,
                    advanced_analyze_url(
                        url,
                        virustotal_api_key,
                        use_virustotal,
                        submit_to_virustotal,
                        include_network,
                    ),
                ).result()
        return loop.run_until_complete(
            advanced_analyze_url(
                url,
                virustotal_api_key,
                use_virustotal,
                submit_to_virustotal,
                include_network,
            )
        )
    except Exception:
        return asyncio.run(
            advanced_analyze_url(
                url,
                virustotal_api_key,
                use_virustotal,
                submit_to_virustotal,
                include_network,
            )
        )


def _advanced_signals(virustotal: dict, network: dict) -> list[dict]:
    signals = []
    vt_stats = virustotal.get("stats") or {}
    vt_malicious = int(vt_stats.get("malicious", 0) or 0)
    vt_suspicious = int(vt_stats.get("suspicious", 0) or 0)

    if vt_malicious >= 1:
        score = 100 if vt_malicious >= 5 else 75
        severity = "critical" if score == 100 else "high"
        signals.append(
            make_signal(
                "virustotal_malicious_detections",
                severity,
                score,
                "VirusTotal vendors have flagged this URL as malicious.",
                {"malicious": vt_malicious, "suspicious": vt_suspicious},
            )
        )
    elif vt_suspicious >= 1:
        signals.append(
            make_signal(
                "virustotal_suspicious_detections",
                "medium",
                30,
                "VirusTotal vendors reported suspicious detections for this URL.",
                {"suspicious": vt_suspicious},
            )
        )

    dns = network.get("dns", {}) if isinstance(network, dict) else {}
    if dns.get("minimum_ttl") is not None and dns["minimum_ttl"] <= 300:
        signals.append(
            make_signal(
                "low_dns_ttl",
                "medium",
                12,
                "Domain uses a low DNS TTL, which can indicate quickly changing infrastructure.",
                {"minimum_ttl": dns["minimum_ttl"]},
            )
        )

    rdap = network.get("whois_rdap", {}) if isinstance(network, dict) else {}
    if rdap.get("age_days") is not None and rdap["age_days"] <= 30:
        signals.append(
            make_signal(
                "newly_registered_domain",
                "high",
                35,
                "Domain registration appears very recent.",
                {"age_days": rdap["age_days"]},
            )
        )

    tls = network.get("tls_certificate", {}) if isinstance(network, dict) else {}
    if tls.get("age_days") is not None and tls["age_days"] <= 14:
        signals.append(
            make_signal(
                "new_tls_certificate",
                "medium",
                12,
                "TLS certificate is very new.",
                {"age_days": tls["age_days"], "issuer": tls.get("issuer")},
            )
        )
    if tls.get("expires_in_days") is not None and tls["expires_in_days"] < 0:
        signals.append(
            make_signal(
                "expired_tls_certificate",
                "medium",
                18,
                "TLS certificate is expired.",
                {"expires_in_days": tls["expires_in_days"]},
            )
        )

    redirect_chain = network.get("redirect_chain", []) if isinstance(network, dict) else []
    cross_domain_redirects = [item for item in redirect_chain if item.get("cross_domain")]
    if cross_domain_redirects:
        signals.append(
            make_signal(
                "cross_domain_redirect_chain",
                "medium",
                20,
                "Redirect chain moves across registrable domains.",
                {"redirects": len(cross_domain_redirects)},
            )
        )

    content_scan = network.get("content_scan", {}) if isinstance(network, dict) else {}
    if isinstance(content_scan, dict):
        for finding in content_scan.get("findings", []) or []:
            signals.append(
                make_signal(
                    finding.get("signal", "content_scan_finding"),
                    finding.get("severity", "low"),
                    finding.get("score", 0),
                    finding.get("reason", "Fetched page content produced a suspicious signal."),
                    finding.get("details", {}),
                )
            )

    return signals


def _combined_score(base_score: int, advanced_signals: list[dict]) -> int:
    if not advanced_signals:
        return base_score
    advanced_score = sum(max(0, int(signal.get("score", 0))) for signal in advanced_signals)
    return max(base_score, min(100, base_score + advanced_score))


def _advanced_confidence(base_confidence: float, risk_score: int, advanced_signals: list[dict]) -> float:
    if not advanced_signals:
        return base_confidence
    signal_boost = min(0.2, len(advanced_signals) * 0.05)
    score_boost = min(0.1, risk_score / 1000)
    return round(min(0.99, max(base_confidence, 0.72 + signal_boost + score_boost)), 2)


def _advanced_explanation(base_analysis: dict, virustotal: dict, advanced_signals: list[dict], classification: str) -> str:
    if advanced_signals:
        strongest = sorted(advanced_signals, key=lambda item: item.get("score", 0), reverse=True)[:3]
        reasons = "; ".join(signal["reason"] for signal in strongest)
        return f"{classification} after advanced enrichment: {reasons}"
    if virustotal.get("status") == "missing_api_key":
        return f"Advanced enrichment ran without VirusTotal; base result remains {base_analysis['classification']}."
    return f"Advanced enrichment found no stronger external evidence; base result remains {base_analysis['classification']}."

