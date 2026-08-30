from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from api.routes import router as api_router
from engine.virustotal import get_default_vt_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure client is initialized
    vt_client = get_default_vt_client()
    yield
    # Shutdown: cleanly close HTTP clients
    await vt_client.close()


app = FastAPI(title="CipherX API", lifespan=lifespan)

# Setup CORS
allowed_origins_env = os.getenv("CORS_ORIGINS", "")
allowed_origins = [origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()] if allowed_origins_env else [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
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

