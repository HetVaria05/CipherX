# 👥 CipherX — 4-Member Team Role Breakdown & Implementation Guide

---

## 📌 Team Role & Feature Matrix

```
+---------------------------------------------------------------------------------------------------------+
| Member 1: AI / Machine Learning & Threat Detection Engine                                                |
| Member 2: Threat Intelligence, VirusTotal & Network Infrastructure Engineering                          |
| Member 3: Full-Stack Authentication, MongoDB Architecture & Quota Monetization                           |
| Member 4: Frontend UI/UX, Security Telemetry, Multilingual i18n & Interactive Shield                     |
+---------------------------------------------------------------------------------------------------------+
```

---

## 👤 Member 1: AI / ML & Adversarial Detection Engine Lead

### 💡 What this member explains to judges:
> *"I designed and engineered the core AI detection pipelines in CipherX. Instead of treating URLs as simple text strings or depending on slow external APIs, our engine computes 28 structural, lexical, entropy, and adversarial signals locally in under 15ms. I trained a Random Forest model on 99,999 URLs (backed by a benchmark pool of ~987,000 URLs), achieving a 0.9842 ROC-AUC score, and built custom algorithms to catch Cyrillic homoglyphs and typosquatted domains."*

### 🛠️ Technologies Used:
- **Python 3.10+ / Scikit-Learn / Joblib**: Random Forest Classifier & model persistence.
- **NumPy / Math (Shannon Entropy)**: Randomness and complexity scoring of domains and paths.
- **Levenshtein Distance Algorithms**: Brand impersonation similarity scoring.
- **Regular Expressions & Unicode Character Maps**: Cyrillic/Greek confusable homoglyph decoding.

### 📂 Code Location & Files to Show Judges:
- [`cipherx/backend/engine/ml_classifier.py`](file:///d:/Mecia%20Hacks/cipherx/backend/engine/ml_classifier.py): 28-feature extraction logic and inference engine.
- [`cipherx/backend/engine/detector.py`](file:///d:/Mecia%20Hacks/cipherx/backend/engine/detector.py): Multi-signal weighted risk scoring engine (0–100 scale).
- [`cipherx/backend/engine/url_utils.py`](file:///d:/Mecia%20Hacks/cipherx/backend/engine/url_utils.py): Homoglyph detection, brand distance calculator, and entropy analysis.
- [`cipherx/backend/models/model_meta.json`](file:///d:/Mecia%20Hacks/cipherx/backend/models/model_meta.json): Feature column mapping and evaluation metrics (`ROC-AUC: 0.9842`).

---

## 👤 Member 2: Threat Intelligence & Network Infrastructure Lead

### 💡 What this member explains to judges:
> *"I engineered the deep threat intelligence and asynchronous network infrastructure inspection layer. When a user runs an Advanced Scan, CipherX initiates parallel asynchronous probes to resolve DNS records (TTL, A/AAAA), TLS certificate validity and age, RDAP domain registration age, and queries VirusTotal v3 for multi-vendor AV consensus with zero-dependency fallback."*

### 🛠️ Technologies Used:
- **VirusTotal v3 REST API**: Vendor threat consensus, detection breakdown, and category tags.
- **Asynchronous Python / `urllib` / `httpx` / `asyncio`**: Non-blocking concurrent requests.
- **Socket / SSL / TLS Probing (`ssl`, `socket`)**: Extracting certificate issuer, age, and validity.
- **abuse.ch URLhaus Threat Feed API**: Real-time active malware URL feeds.

### 📂 Code Location & Files to Show Judges:
- [`cipherx/backend/engine/virustotal.py`](file:///d:/Mecia%20Hacks/cipherx/backend/engine/virustotal.py): VirusTotal v3 asynchronous client with standard library fallback and threat scoring.
- [`cipherx/backend/engine/network_intel.py`](file:///d:/Mecia%20Hacks/cipherx/backend/engine/network_intel.py): DNS resolution, TLS handshake probes, and RDAP registration lookup.
- [`cipherx/backend/engine/threat_intel.py`](file:///d:/Mecia%20Hacks/cipherx/backend/engine/threat_intel.py): abuse.ch URLhaus real-time feed integration and local IOC matching.
- [`cipherx/backend/engine/advanced.py`](file:///d:/Mecia%20Hacks/cipherx/backend/engine/advanced.py): Orchestrator combining base scan findings with deep network intelligence.

---

## 👤 Member 3: Backend APIs, Database & User Management Lead

### 💡 What this member explains to judges:
> *"I built the backend API architecture, database persistence, and commercial quota management using FastAPI and MongoDB. The system enforces a 3-scan daily free tier, manages authenticated users with salted SHA-256 password hashing, supports Google Account OAuth sign-in, and caches historical scan results for 24 hours to prevent duplicate compute."*

### 🛠️ Technologies Used:
- **FastAPI / Pydantic / Uvicorn**: High-performance asynchronous REST API framework.
- **MongoDB (PyMongo)**: User accounts, scan history (`scans`), 24h caching (`scan_cache`), and daily quotas (`user_quotas`).
- **Cryptographic Security (`hashlib`, `secrets`)**: Salted SHA-256 password storage.
- **OAuth / Google Auth Workflow**: Seamless single-sign-on provisioning.

### 📂 Code Location & Files to Show Judges:
- [`cipherx/backend/database.py`](file:///d:/Mecia%20Hacks/cipherx/backend/database.py): MongoDB collections, user CRUD, Google auth provisioning, and quota reset logic.
- [`cipherx/backend/api/routes.py`](file:///d:/Mecia%20Hacks/cipherx/backend/api/routes.py): REST endpoints (`/api/analyze`, `/api/advanced-analyze`, `/api/auth/*`, `/api/user/quota`).
- [`cipherx/backend/main.py`](file:///d:/Mecia%20Hacks/cipherx/backend/main.py): FastAPI server bootstrap, CORS configuration, and background initialization.

---

## 👤 Member 4: Frontend UI/UX, Multilingual i18n & Web Shield Lead

### 💡 What this member explains to judges:
> *"I created the modern cybersecurity user experience using React, Tailwind CSS, and Lucide icons. I developed the dynamic Result Dashboard with real-time risk gauges, the interactive Threat Monitor web shield simulation, the multilingual localization system (supporting English, Gujarati, and Hindi), and the Google Sign-in & Pricing modal."*

### 🛠️ Technologies Used:
- **React.js (Vite) / Context API**: State management (`AuthContext`, `LanguageContext`).
- **Tailwind CSS & Glassmorphism UI**: High-contrast, dark-mode cybersecurity visual design.
- **Custom i18n Engine**: Dynamic client-side internationalization across 3 languages without external dependencies.
- **Lucide React Icons**: Cohesive, modern security interface components.

### 📂 Code Location & Files to Show Judges:
- [`cipherx/frontend/src/App.jsx`](file:///d:/Mecia%20Hacks/cipherx/frontend/src/App.jsx): Main app view, tab navigation, Threat Monitor modal, and bottom security advisory.
- [`cipherx/frontend/src/components/ResultDashboard.jsx`](file:///d:/Mecia%20Hacks/cipherx/frontend/src/components/ResultDashboard.jsx): Score gauge, VirusTotal breakdown, and 28 heuristic feature grid.
- [`cipherx/frontend/src/components/AuthModal.jsx`](file:///d:/Mecia%20Hacks/cipherx/frontend/src/components/AuthModal.jsx): Email/password and Google authentication modal.
- [`cipherx/frontend/src/i18n/translations.js`](file:///d:/Mecia%20Hacks/cipherx/frontend/src/i18n/translations.js): Complete English, Gujarati, and Hindi translation dictionaries.
- [`cipherx/frontend/src/context/AuthContext.jsx`](file:///d:/Mecia%20Hacks/cipherx/frontend/src/context/AuthContext.jsx): User state and real-time quota synchronization.
