from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
from engine.detector import analyze_url

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str

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
    explanation: str

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(req: AnalyzeRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    try:
        # Pass to the detection engine interface
        result = analyze_url(req.url)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "CipherX API"}
