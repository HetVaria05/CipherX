from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from engine.advanced import advanced_analyze_url
from engine.detector import analyze_url
from database import save_scan, get_recent_scans, get_scan_stats
from starlette.concurrency import run_in_threadpool

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str

class AdvancedAnalyzeRequest(BaseModel):
    url: str
    virustotal_api_key: Optional[str] = None
    use_virustotal: bool = True
    submit_to_virustotal: bool = False
    include_network: bool = True
    user_id: Optional[str] = "guest_user"

class AnalyzeResponse(BaseModel):
    url: str
    normalized_url: str
    risk_score: int
    classification: str
    confidence: float
    signals: List[Dict[str, Any]]
    features: Dict[str, Any]
    adversarial_findings: List[Dict[str, Any]]
    brand_analysis: Dict[str, Any]
    network: Optional[Dict[str, Any]] = None
    explanation: str

class AdvancedAnalyzeResponse(BaseModel):
    url: str
    normalized_url: str
    risk_score: int
    classification: str
    confidence: float
    signals: List[Dict[str, Any]]
    base_analysis: Dict[str, Any]
    advanced: Dict[str, Any]
    explanation: str
    quota: Optional[Dict[str, Any]] = None

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(req: AnalyzeRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    try:
        # Pass to the detection engine interface
        result = analyze_url(req.url)
        # Automatically persist scan in MongoDB / Database layer
        save_scan(result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/advanced-analyze", response_model=AdvancedAnalyzeResponse)
async def advanced_analyze_endpoint(req: AdvancedAnalyzeRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    user_identifier = req.user_id or "guest_user"

    try:
        # 1. Check MongoDB Cache first (24h TTL) to save external API calls
        from database import get_cached_scan, cache_scan_result, get_user_quota, consume_user_quota
        cached_result = get_cached_scan(req.url)
        current_quota = get_user_quota(user_identifier)

        if cached_result:
            cached_result["quota"] = current_quota
            cached_result["cached"] = True
            return cached_result

        # 2. Check and enforce 3-scan daily quota
        quota_allowed = consume_user_quota(user_identifier)
        if not quota_allowed:
            # When quota exhausted, fallback to base analysis without burning VT credits
            base = analyze_url(req.url)
            save_scan(base)
            return {
                "url": base["url"],
                "normalized_url": base["normalized_url"],
                "risk_score": base["risk_score"],
                "classification": base["classification"],
                "confidence": base["confidence"],
                "signals": base["signals"],
                "base_analysis": base,
                "advanced": {
                    "virustotal": {"status": "quota_exceeded", "summary": "Daily 3-scan advanced quota reached. Displaying AI engine scan."},
                    "network": base.get("network", {}),
                    "signals": []
                },
                "explanation": f"[Quota Limit] {base['explanation']}",
                "quota": get_user_quota(user_identifier)
            }

        # 3. Perform full advanced scan (VT + Network Enrichment)
        result = await run_in_threadpool(
            advanced_analyze_url,
            req.url,
            req.virustotal_api_key,
            req.use_virustotal,
            req.submit_to_virustotal,
            req.include_network,
        )
        
        # Attach updated quota & cache the result
        result["quota"] = get_user_quota(user_identifier)
        cache_scan_result(req.url, result)
        save_scan(result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recent")
async def recent_scans_endpoint(limit: int = Query(default=10, ge=1, le=50)):
    """
    Fetches the most recent threat scan history.
    """
    return get_recent_scans(limit=limit)

@router.get("/stats")
async def stats_endpoint():
    """
    Returns aggregated threat scan statistics and database connection status.
    """
    return get_scan_stats()

@router.get("/health")
async def health_check():
    stats = get_scan_stats()
    return {
        "status": "ok",
        "service": "CipherX API",
        "database": stats.get("db_status", "unknown")
    }
