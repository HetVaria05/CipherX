# CLAUDE.md — CipherX Codebase Navigator

## Project Overview
CipherX is a multi-layered URL threat detection system with a FastAPI backend and React/Vite frontend.
The detection engine is a 7-layer synchronous-async hybrid pipeline ending in a Random Forest ML classifier.

---

## Repository Layout

```
cipherx/
├── backend/
│   ├── main.py                  # FastAPI app entrypoint, CORS, lifespan
│   ├── database.py              # MongoDB (pymongo) + in-memory fallback + quota/cache logic
│   ├── requirements.txt         # Python deps (pinned by range, not exact)
│   ├── api/
│   │   └── routes.py            # All HTTP endpoints (/analyze, /advanced-analyze, /recent, /stats, /health)
│   ├── engine/
│   │   ├── detector.py          # Main pipeline orchestrator (analyze_url async)
│   │   ├── advanced.py          # Advanced scan: concurrent VT + Network gather
│   │   ├── virustotal.py        # Async VirusTotal v3 client + TTL cache
│   │   ├── network_intel.py     # DNS/TLS/RDAP/redirect/content probing (sync, run via asyncio.to_thread)
│   │   ├── ml_classifier.py     # Random Forest inference (lazy joblib load)
│   │   ├── lexical.py           # URL structural/lexical signal extraction
│   │   ├── adversarial.py       # @-symbol, subdomain deception, unicode tricks
│   │   ├── brand.py             # Brand impersonation + fuzzy matching
│   │   ├── features.py          # NormalizedURL → feature dict (all signals consume this)
│   │   ├── risk.py              # Signal aggregation → score/classify/confidence
│   │   ├── signals.py           # make_signal() factory
│   │   ├── threat_intel.py      # Local IOC DB + URLhaus live feed
│   │   └── url_utils.py         # URL normalization → NormalizedURL dataclass
│   ├── scripts/
│   │   └── train_model.py       # ML training: merges datasets, trains RF, saves url_classifier.joblib
│   ├── data/
│   │   └── url_dataset.csv      # 100k merged dataset (NOT committed to git)
│   └── tests/
│       └── test_api.py          # pytest + FastAPI TestClient (network ops monkeypatched)
└── frontend/
    ├── src/
    │   ├── App.jsx              # Root component, all state management
    │   ├── services/api.js      # Axios client (VITE_API_URL env var)
    │   ├── components/          # UI: Navbar, ResultDashboard, ScanInput, etc.
    │   ├── context/             # React context (if any theme/auth)
    │   └── i18n/               # EN/HI/GU translation JSON files
    ├── .env.example
    └── vite.config.js
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend runtime | Python 3.10+ (union types `X | Y` used — requires 3.10+) |
| Web framework | FastAPI 0.100+ |
| ASGI server | Uvicorn |
| HTTP client | httpx (async) |
| Database | MongoDB Atlas via pymongo (sync calls) |
| ML | scikit-learn RandomForestClassifier + joblib |
| Feature engineering | pandas (train only), numpy (inference) |
| DNS resolution | dnspython + aiodns |
| TLD parsing | tldextract |
| In-process cache | cachetools.TTLCache |
| Frontend | React 18 + Vite |
| Frontend HTTP | Axios |
| Styling | Tailwind CSS |
| i18n | react-i18next |

---

## Environment Variables

### Backend (`cipherx/backend/.env`)
```
MONGODB_URI=mongodb+srv://...
VT_API_KEY=...
CORS_ORIGINS=http://localhost:5173,http://localhost:5174
```

### Frontend (`cipherx/frontend/.env.local`)
```
VITE_API_URL=http://localhost:8000/api
```

**IMPORTANT**: `.env` files are in `.gitignore`. Never commit real keys.

---

## Run Commands

### Backend
```bash
cd cipherx/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd cipherx/frontend
npm install
npm run dev
```

### Train ML Model
```bash
cd cipherx/backend
python scripts/train_model.py
```

### Run Tests
```bash
cd cipherx/backend
pytest tests/ -v
```

---

## Critical Architecture Rules

1. **`NormalizedURL` is the universal input.** Every engine module takes a `NormalizedURL` dataclass from `url_utils.normalize_url()`.
2. **All network I/O in `network_intel.py` is BLOCKING.** Always called via `asyncio.to_thread()`. Do NOT convert it to async.
3. **ML classifier uses lazy imports.** If `url_classifier.joblib` is missing, `predict_ml_risk()` returns `None` gracefully.
4. **MongoDB is optional.** `get_db()` returns `None` on connection failure. All callers handle `None`.
5. **Signal deduplication** uses `(signal_name, json(details))` — details must be JSON-serializable.
6. **`user_id` is client-supplied and not authenticated.**

---

## Known Bugs (DO NOT REGRESS)

| Bug | Location |
|---|---|
| Shared `guest_user` quota exhausted by any anonymous user | `routes.py:73` |
| VT client created at shutdown instead of startup | `main.py:15` |
| Cached scan may fail Pydantic validation if schema changed | `routes.py:80-83` |
| `brand_analysis.similarity_score` null crash in ResultDashboard | `ResultDashboard.jsx` |
| `checkHealth` has no error handling | `api.js:56` |
| `asyncio.get_event_loop()` deprecated in Python 3.12 | `virustotal.py:228` |
| MongoDB retries on every request when Atlas down | `database.py` |

---

## Key Data Flow

```
POST /api/advanced-analyze
  routes.py → check MongoDB cache (24h TTL)
  routes.py → check/consume user quota (3/day)
  advanced.py → analyze_url() [base 7-layer pipeline]
  advanced.py → asyncio.gather(VT scan, Network Intel)
  advanced.py → merge signals, re-score
  routes.py → cache result in MongoDB
  routes.py → return AdvancedAnalyzeResponse
```

---

## Debugging Patterns

- **500 on /advanced-analyze** → Check `/api/health` → if `database: in_memory_fallback`, MongoDB is down.
- **ML signals missing** → Check `engine/url_classifier.joblib` exists. Run `train_model.py` to regenerate.
- **VT returns `missing_api_key`** → `VT_API_KEY` not in backend `.env`. Restart uvicorn after adding.
- **CORS error** → Ensure `CORS_ORIGINS` in `.env` matches exact Vite dev server URL:port.
- **Tests fail on import** → Run pytest from `cipherx/backend/` directory, not repo root.

---

## Performance Expectations

| Scenario | Typical Latency |
|---|---|
| `/analyze` (heuristic + ML only) | 50–300ms |
| `/advanced-analyze` cold | 2–8s (VT + DNS probes in parallel) |
| `/advanced-analyze` MongoDB cache hit | 10–30ms |
| ML inference | 1–5ms |
| DNS resolution | 100–500ms |

---

## Do NOT Change Before Demo

- `engine/risk.py` — scoring thresholds are tuned
- `engine/threat_intel.py` — IOC structure used by tests
- `engine/virustotal.py` TTLCache maxsize (2000)
- Any monkeypatch targets in `tests/test_api.py`
