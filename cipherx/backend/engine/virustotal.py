import asyncio
import base64
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dotenv import load_dotenv

load_dotenv()

try:
    import httpx
except ImportError:
    httpx = None

try:
    from cachetools import TTLCache
except ImportError:
    class TTLCache(dict):
        def __init__(self, maxsize: int = 2000, ttl: int = 3600):
            super().__init__()
            self.maxsize = maxsize
            self.ttl = ttl
            self._times = {}

        def __getitem__(self, key):
            if key in self._times:
                if time.monotonic() - self._times[key] > self.ttl:
                    del self[key]
                    del self._times[key]
                    raise KeyError(key)
            return super().__getitem__(key)

        def __setitem__(self, key, value):
            if len(self) >= self.maxsize and key not in self:
                oldest = min(self._times, key=self._times.get)
                del self[oldest]
                del self._times[oldest]
            self._times[key] = time.monotonic()
            super().__setitem__(key, value)

        def __contains__(self, key):
            try:
                self[key]
                return True
            except KeyError:
                return False


logger = logging.getLogger(__name__)
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def get_configured_api_key() -> str | None:
    return os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")


def build_url_identifier(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


class VirusTotalClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        timeout_s: float = 12.0,
        max_concurrency: int = 3,
        cache_ttl_s: int = 3600,
    ):
        self.api_key = (api_key or get_configured_api_key() or "").strip()
        self.sem = asyncio.Semaphore(max_concurrency)
        self.cache = TTLCache(maxsize=2000, ttl=cache_ttl_s)
        self.timeout_s = timeout_s
        self._client: Optional[Any] = None

    def _get_client(self) -> Any:
        if httpx is None:
            raise RuntimeError("httpx is required for VirusTotalClient")
        if self._client is None or self._client.is_closed:
            headers = {
                "accept": "application/json",
                "x-tool": "CipherX",
            }
            if self.api_key:
                headers["x-apikey"] = self.api_key
            self._client = httpx.AsyncClient(
                base_url=VT_BASE_URL,
                timeout=httpx.Timeout(self.timeout_s, connect=5.0),
                trust_env=False,
                headers=headers,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _request_urllib(self, method: str, endpoint: str, data: Optional[bytes] = None, headers: Optional[dict] = None) -> tuple[int, dict]:
        import json
        import urllib.request
        import urllib.error

        url = f"{VT_BASE_URL}{endpoint}"
        req_headers = {
            "accept": "application/json",
            "x-tool": "CipherX",
        }
        if self.api_key:
            req_headers["x-apikey"] = self.api_key
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        def _do_req():
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    body = resp.read().decode("utf-8")
                    return resp.status, json.loads(body) if body else {}
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8")
                try:
                    payload = json.loads(body) if body else {}
                except Exception:
                    payload = {}
                return e.code, payload

        return await asyncio.to_thread(_do_req)

    async def get_url_report(self, url: str) -> dict:
        if not self.api_key:
            return {
                "enabled": False,
                "status": "missing_api_key",
                "summary": "VirusTotal scan skipped because no API key was provided.",
            }

        url_id = build_url_identifier(url)
        cache_key = f"vt:url:{url_id}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        async with self.sem:
            try:
                if httpx is not None:
                    client = self._get_client()
                    response = await client.get(
                        f"/urls/{url_id}",
                        headers={"x-apikey": self.api_key} if self.api_key else {},
                    )
                    status_code = response.status_code
                    payload = response.json() if status_code == 200 else {}
                else:
                    status_code, payload = await self._request_urllib("GET", f"/urls/{url_id}")

                if status_code == 404:
                    out = {
                        "enabled": True,
                        "status": "not_found",
                        "summary": "No VirusTotal URL report exists yet.",
                    }
                elif status_code in (401, 403):
                    out = {
                        "enabled": True,
                        "status": "auth_failed",
                        "summary": "VirusTotal rejected the API key or account permissions.",
                    }
                elif status_code == 429:
                    out = {
                        "enabled": True,
                        "status": "rate_limited",
                        "summary": "VirusTotal rate limit reached for this API key.",
                    }
                elif status_code == 200:
                    out = _parse_vt_payload(payload)
                else:
                    out = {
                        "enabled": True,
                        "status": "error",
                        "summary": f"VirusTotal lookup returned status {status_code}.",
                    }
            except Exception as err:
                out = {
                    "enabled": True,
                    "status": "error",
                    "summary": "VirusTotal lookup failed.",
                    "error": str(err),
                }

        self.cache[cache_key] = out
        return out

    async def submit_url(self, url: str) -> dict:
        if not self.api_key:
            return {"status": "missing_api_key", "summary": "API key required for submission."}

        async with self.sem:
            try:
                import urllib.parse
                post_data = urllib.parse.urlencode({"url": url}).encode("utf-8")
                
                if httpx is not None:
                    client = self._get_client()
                    response = await client.post(
                        "/urls",
                        data={"url": url},
                        headers={
                            "content-type": "application/x-www-form-urlencoded",
                            "x-apikey": self.api_key,
                        },
                    )
                    status_code = response.status_code
                    payload = response.json() if status_code == 200 else {}
                else:
                    status_code, payload = await self._request_urllib(
                        "POST",
                        "/urls",
                        data=post_data,
                        headers={"content-type": "application/x-www-form-urlencoded"}
                    )

                if status_code in (401, 403):
                    return {"status": "auth_failed", "summary": "VirusTotal authentication failed."}
                if status_code == 429:
                    return {"status": "rate_limited", "summary": "VirusTotal rate limit reached."}
                if status_code == 200:
                    return {
                        "status": "submitted",
                        "analysis_id": payload.get("data", {}).get("id"),
                        "summary": "URL submitted to VirusTotal for analysis.",
                    }
                return {"status": "error", "summary": f"VirusTotal submission returned status {status_code}."}
            except Exception as err:
                return {"status": "error", "summary": "VirusTotal submission failed.", "error": str(err)}

    async def scan_url_report(self, url: str, submit_if_missing: bool = False) -> dict:
        report = await self.get_url_report(url)
        if report.get("status") == "not_found" and submit_if_missing:
            submission = await self.submit_url(url)
            report["submission"] = submission
            if submission.get("status") == "submitted":
                report["status"] = "submitted"
                report["summary"] = "URL submitted to VirusTotal. Re-run advanced scan after analysis completes."
        return report


_default_vt_client: Optional[VirusTotalClient] = None


def get_default_vt_client() -> VirusTotalClient:
    global _default_vt_client
    if _default_vt_client is None:
        _default_vt_client = VirusTotalClient()
    return _default_vt_client


async def scan_url_report(
    url: str,
    api_key: str | None = None,
    submit_if_missing: bool = False,
) -> dict:
    key = (api_key or get_configured_api_key() or "").strip()
    if not key:
        return {
            "enabled": False,
            "status": "missing_api_key",
            "summary": "VirusTotal scan skipped because no API key was provided.",
        }

    client = VirusTotalClient(api_key=key) if api_key else get_default_vt_client()
    try:
        return await client.scan_url_report(url, submit_if_missing=submit_if_missing)
    finally:
        if api_key:
            await client.close()


def scan_url_report_sync(
    url: str,
    api_key: str | None = None,
    submit_if_missing: bool = False,
) -> dict:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run,
                    scan_url_report(url, api_key, submit_if_missing),
                ).result()
        return loop.run_until_complete(scan_url_report(url, api_key, submit_if_missing))
    except Exception:
        return asyncio.run(scan_url_report(url, api_key, submit_if_missing))


def _parse_vt_payload(payload: dict) -> dict:
    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    vendors_total = sum(int(value or 0) for value in stats.values())
    verdict = _verdict_from_stats(malicious, suspicious)
    
    # Calculate VT-specific Risk Score (0-100)
    if vendors_total > 0:
        vt_risk_score = min(100, int((malicious * 12) + (suspicious * 5)))
    else:
        vt_risk_score = 0

    # Extract engine flags (malicious or suspicious engine hits)
    engine_results = attributes.get("last_analysis_results", {}) or {}
    flagged_engines = []
    for engine_name, eng in engine_results.items():
        category = eng.get("category")
        if category in ("malicious", "suspicious"):
            flagged_engines.append({
                "engine": engine_name,
                "category": category,
                "result": eng.get("result") or category,
                "method": eng.get("method", "blacklist")
            })

    # Sort flagged engines alphabetically
    flagged_engines.sort(key=lambda x: (x["category"] != "malicious", x["engine"]))

    return {
        "enabled": True,
        "status": "found",
        "verdict": verdict,
        "vt_risk_score": vt_risk_score,
        "url_id": payload.get("data", {}).get("id"),
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": vendors_total,
        },
        "flagged_engines": flagged_engines,
        "reputation": attributes.get("reputation", 0),
        "tags": attributes.get("tags", []),
        "last_analysis_date": _format_timestamp(attributes.get("last_analysis_date")),
        "last_final_url": attributes.get("last_final_url"),
        "categories": attributes.get("categories", {}),
        "total_votes": attributes.get("total_votes", {}),
        "summary": _summary(verdict, malicious, suspicious, vendors_total),
    }


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

