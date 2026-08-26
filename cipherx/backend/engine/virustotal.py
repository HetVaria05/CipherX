import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


VT_BASE_URL = "https://www.virustotal.com/api/v3"


def get_configured_api_key() -> str | None:
    return os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")


def build_url_identifier(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def scan_url_report(url: str, api_key: str | None = None, submit_if_missing: bool = False) -> dict:
    key = (api_key or get_configured_api_key() or "").strip()
    if not key:
        return {
            "enabled": False,
            "status": "missing_api_key",
            "summary": "VirusTotal scan skipped because no API key was provided.",
        }

    report = _get_url_report(url, key)
    if report.get("status") == "not_found" and submit_if_missing:
        submission = _submit_url(url, key)
        report["submission"] = submission
        if submission.get("status") == "submitted":
            report["status"] = "submitted"
            report["summary"] = "URL submitted to VirusTotal. Re-run advanced scan after analysis completes."
    return report


def _get_url_report(url: str, api_key: str) -> dict:
    url_id = build_url_identifier(url)
    request = urllib.request.Request(
        f"{VT_BASE_URL}/urls/{url_id}",
        headers={
            "accept": "application/json",
            "x-apikey": api_key,
            "x-tool": "CipherX",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return _http_error_result(err)
    except Exception as err:
        return {
            "enabled": True,
            "status": "error",
            "summary": "VirusTotal lookup failed.",
            "error": str(err),
        }

    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    vendors_total = sum(int(value or 0) for value in stats.values())
    verdict = _verdict_from_stats(malicious, suspicious)

    return {
        "enabled": True,
        "status": "found",
        "verdict": verdict,
        "url_id": payload.get("data", {}).get("id"),
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": vendors_total,
        },
        "reputation": attributes.get("reputation"),
        "last_analysis_date": _format_timestamp(attributes.get("last_analysis_date")),
        "last_final_url": attributes.get("last_final_url"),
        "categories": attributes.get("categories", {}),
        "total_votes": attributes.get("total_votes", {}),
        "summary": _summary(verdict, malicious, suspicious, vendors_total),
    }


def _submit_url(url: str, api_key: str) -> dict:
    data = urllib.parse.urlencode({"url": url}).encode("utf-8")
    request = urllib.request.Request(
        f"{VT_BASE_URL}/urls",
        data=data,
        headers={
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-apikey": api_key,
            "x-tool": "CipherX",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return _http_error_result(err)
    except Exception as err:
        return {"status": "error", "summary": "VirusTotal submission failed.", "error": str(err)}

    return {
        "status": "submitted",
        "analysis_id": payload.get("data", {}).get("id"),
        "summary": "URL submitted to VirusTotal for analysis.",
    }


def _http_error_result(err: urllib.error.HTTPError) -> dict:
    status = "not_found" if err.code == 404 else "error"
    if err.code in (401, 403):
        status = "auth_failed"
    if err.code == 429:
        status = "rate_limited"

    return {
        "enabled": True,
        "status": status,
        "http_status": err.code,
        "summary": _http_error_summary(err.code),
    }


def _http_error_summary(status_code: int) -> str:
    if status_code == 404:
        return "No VirusTotal URL report exists yet."
    if status_code in (401, 403):
        return "VirusTotal rejected the API key or account permissions."
    if status_code == 429:
        return "VirusTotal rate limit reached for this API key."
    return "VirusTotal request failed."


def _verdict_from_stats(malicious: int, suspicious: int) -> str:
    if malicious >= 5:
        return "critical"
    if malicious >= 1:
        return "malicious"
    if suspicious >= 2:
        return "suspicious"
    if suspicious == 1:
        return "caution"
    return "clean"


def _summary(verdict: str, malicious: int, suspicious: int, total: int) -> str:
    if verdict in {"critical", "malicious"}:
        return f"VirusTotal vendors flagged this URL ({malicious} malicious, {suspicious} suspicious out of {total})."
    if verdict in {"suspicious", "caution"}:
        return f"VirusTotal found cautionary detections ({malicious} malicious, {suspicious} suspicious out of {total})."
    return f"VirusTotal did not report malicious detections across {total} vendors."


def _format_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None
