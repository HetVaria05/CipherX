from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from database import (
    get_cached_scan,
    cache_scan_result,
    get_user_quota,
    consume_user_quota,
    save_scan,
    get_recent_scans,
    get_scan_stats,
    create_user,
    authenticate_user,
)
from engine.advanced import advanced_analyze_url
from engine.detector import analyze_url

router = APIRouter()


class SignUpRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None


class SignInRequest(BaseModel):
    email: str
    password: str


class GoogleAuthRequest(BaseModel):
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    google_id: Optional[str] = None


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
    scan_duration_ms: Optional[float] = None


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
    scan_duration_ms: Optional[float] = None


@router.post("/auth/signup")
async def signup_endpoint(req: SignUpRequest):
    try:
        user = create_user(req.email, req.password, req.full_name)
        return {"status": "ok", "user": user}
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=500, detail="Registration failed.")


@router.post("/auth/signin")
async def signin_endpoint(req: SignInRequest):
    try:
        user = authenticate_user(req.email, req.password)
        # Fetch quota for the user
        quota = get_user_quota(user["email"])
        return {"status": "ok", "user": user, "quota": quota}
    except ValueError as err:
        raise HTTPException(status_code=401, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=500, detail="Authentication failed.")


@router.post("/auth/google")
async def google_auth_endpoint(req: GoogleAuthRequest):
    try:
        from database import get_or_create_google_user
        user = get_or_create_google_user(req.email, req.full_name, req.avatar_url)
        quota = get_user_quota(user["email"])
        return {"status": "ok", "user": user, "quota": quota}
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=500, detail="Google authentication failed.")


@router.get("/auth/me")
async def get_current_user_profile(email: str = Query(..., description="User email")):
    from database import get_user_by_email
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    quota = get_user_quota(user["email"])
    return {"status": "ok", "user": user, "quota": quota}


class UpgradeTierRequest(BaseModel):
    email: str
    tier: str  # 'free', 'pro', 'enterprise'


@router.post("/auth/upgrade")
async def upgrade_tier_endpoint(req: UpgradeTierRequest):
    from database import update_user_tier
    if req.tier not in ("free", "pro", "enterprise"):
        raise HTTPException(status_code=400, detail="Invalid tier specified.")
    success = update_user_tier(req.email, req.tier)
    if not success:
        raise HTTPException(status_code=404, detail="User account not found.")
    return {"status": "ok", "message": f"Successfully updated tier to {req.tier}."}


@router.get("/users")
async def list_users_endpoint(limit: int = Query(default=20, ge=1, le=100)):
    from database import get_all_users
    return get_all_users(limit=limit)


@router.get("/user/quota")
async def user_quota_endpoint(user_id: str = "guest_user", request: Request = None):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    user_identifier = user_id if (user_id and user_id != "guest_user") else f"ip_{client_ip}"
    return get_user_quota(user_identifier)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(req: AnalyzeRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        result = await analyze_url(req.url)
        save_scan(result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/advanced-analyze", response_model=AdvancedAnalyzeResponse)
async def advanced_analyze_endpoint(req: AdvancedAnalyzeRequest, request: Request):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_identifier = req.user_id if (req.user_id and req.user_id != "guest_user") else f"ip_{client_ip}"

    try:
        # 1. Check MongoDB Cache first (24h TTL) to save external API calls
        cached_result = get_cached_scan(req.url)
        current_quota = get_user_quota(user_identifier)

        if cached_result and isinstance(cached_result, dict):
            # Ensure all required fields exist for AdvancedAnalyzeResponse schema
            safe_cached = {
                "url": cached_result.get("url", req.url),
                "normalized_url": cached_result.get("normalized_url", req.url),
                "risk_score": cached_result.get("risk_score", 0),
                "classification": cached_result.get("classification", "LOW"),
                "confidence": cached_result.get("confidence", 0.9),
                "signals": cached_result.get("signals", []),
                "base_analysis": cached_result.get("base_analysis", {}),
                "advanced": cached_result.get("advanced", {}),
                "explanation": cached_result.get("explanation", "Scan retrieved from cache."),
                "quota": current_quota,
                "scan_duration_ms": cached_result.get("scan_duration_ms", 0.0),
            }
            return safe_cached

        # 2. Check and enforce daily scan quota
        quota_allowed = consume_user_quota(user_identifier)
        if not quota_allowed:
            base = await analyze_url(req.url)
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
                    "virustotal": {
                        "status": "quota_exceeded",
                        "summary": "Daily advanced quota reached. Displaying AI engine scan.",
                    },
                    "network": base.get("network", {}),
                    "signals": [],
                },
                "explanation": f"[Quota Limit] {base['explanation']}",
                "quota": get_user_quota(user_identifier),
                "scan_duration_ms": base.get("scan_duration_ms"),
            }

        # 3. Perform full async advanced scan (VT + Network Enrichment concurrently)
        result = await advanced_analyze_url(
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
        "database": stats.get("db_status", "unknown"),
    }

