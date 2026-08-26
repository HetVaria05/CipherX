from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from api.routes import router as api_router

app = FastAPI(title="CipherX API")

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For base prototype, allow all or specific frontend url
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

@app.get("/")
async def root():
    return {
        "message": "Welcome to CipherX API",
        "endpoints": {
            "health": "/api/health",
            "analyze": "/api/analyze (POST)",
            "advanced_analyze": "/api/advanced-analyze (POST)",
            "documentation": "/docs"
        }
      }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
