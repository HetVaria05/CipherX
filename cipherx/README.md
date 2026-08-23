# CipherX - Threat Intelligence Detection

CipherX is a professional cybersecurity web application designed to demonstrate an explainable phishing and threat URL detection engine.

This is the **BASE WEB APPLICATION** built as a modular foundation for the hackathon. It separates the frontend dashboard from the backend API and provides a clear integration boundary for the detection engine.

## What was built
1. **React Frontend (Vite):** A dark-mode, professional cybersecurity dashboard utilizing Tailwind CSS and Lucide icons. Includes a prominent URL analysis form, One-Click Verification, loading states, error handling, and a comprehensive result display (Risk score, confidence, classification, signals, adversarial findings, extracted features, and brand analysis).
2. **FastAPI Backend:** A robust API that serves the frontend, built with Python and FastAPI. Includes input validation, CORS setup, structured JSON responses, and a health check endpoint.
3. **Detection Engine Stub:** An isolated mock engine module where the real detection intelligence will eventually be integrated.

## Project Structure
```
cipherx/
├── frontend/             # React + Vite application
│   ├── src/
│   │   ├── components/   # Reusable UI components
│   │   ├── services/     # API service layer (api.js)
│   │   ├── App.jsx       # Main dashboard layout and logic
│   │   └── index.css     # Tailwind CSS base styles
│   ├── package.json
│   └── tailwind.config.js
├── backend/              # FastAPI application
│   ├── api/              # API router and endpoints
│   ├── engine/           # Detection engine boundary
│   │   ├── detector.py   # Mock engine (REPLACE THIS LATER)
│   ├── tests/            # API health and behavior tests
│   ├── main.py           # FastAPI entrypoint
│   └── requirements.txt
└── README.md
```

## Setup and Run Instructions

### 1. Backend (FastAPI)
The backend runs on Python.

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
*The backend will be available at `http://localhost:8000`*

### 2. Frontend (React + Vite)
The frontend communicates with the backend via environment variables.

```bash
cd frontend
npm install
npm run dev
```
*The frontend will be available at `http://localhost:5173` (or the port Vite provides).*

## Important Boundaries

- **Where is the detection engine interface?**
  Located at `backend/engine/detector.py` -> `analyze_url(url)`. This is where the AI team will plug in `lexical.py`, `adversarial.py`, and the final `aggregator.py`.
- **Where is the API contract defined?**
  Located at `backend/api/routes.py`. The `AnalyzeRequest` and `AnalyzeResponse` Pydantic models define the exact expected JSON structures.
- **What is temporary/mock?**
  The logic inside `backend/engine/detector.py` is entirely a mock implementation for demonstration purposes. It hardcodes responses based on simple string matching (e.g., triggering critical adversarial findings if an `@` symbol is present, or high-risk brand impersonation if `typ` is in the URL). **This file must be replaced by the team's real detection logic.**
