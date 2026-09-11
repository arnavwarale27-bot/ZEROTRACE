# ZEROTRACE - AI Security Investigation Agent for SOC Analysts

ZEROTRACE is a modular, evidence-grounded AI security investigation platform built for SOC analysts. Phase 1 establishes the core project foundation, data schemas, database abstraction layer, modular component placeholders, health check endpoint, and frontend verification interface.

---

## 🏗 Architecture Overview

The system is structured into a FastAPI backend and a Vite+React frontend:

```
ZEROTRACE/
├── .env.example
├── README.md
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI application entrypoint with CORS & API routing
│   │   ├── core/
│   │   │   ├── config.py         # Pydantic BaseSettings configuration loader
│   │   │   └── database.py       # SQLAlchemy engine & session dependency
│   │   ├── db/
│   │   │   ├── base.py           # ORM Declarative Base
│   │   │   └── repository.py     # Generic BaseRepository abstraction pattern
│   │   ├── models/
│   │   │   ├── domain.py         # SQLAlchemy ORM models
│   │   │   └── schemas.py        # Pydantic v2 domain schemas (SecurityEvent, IOC, Incident, Evidence, TimelineEvent, MitreTechnique, InvestigationResult, RecommendedAction)
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── router.py     # API v1 router
│   │   │       └── endpoints/
│   │   │           └── health.py # GET /api/v1/health endpoint
│   │   └── modules/              # Modular component interfaces for future phases
│   │       ├── ingestion/
│   │       ├── normalization/
│   │       ├── extraction/
│   │       ├── correlation/
│   │       ├── enrichment/
│   │       ├── timeline/
│   │       ├── mitre/
│   │       ├── investigation/
│   │       └── dashboard/
│   └── tests/
│       ├── conftest.py           # Pytest fixtures and TestClient setup
│       ├── test_health.py        # Health check endpoint test
│       └── test_schemas.py       # Pydantic schema validation tests
└── frontend/                     # React (Vite) Verification Frontend
    ├── src/
    │   ├── App.jsx               # Backend connectivity verification UI
    │   ├── services/
    │   │   └── api.js            # Health check client
    │   └── index.css             # Dark SOC operation themes
    ├── package.json
    └── vite.config.js
```

---

## 🚦 Data Models & Schemas

The system defines clean Pydantic v2 schemas and corresponding ORM models for 8 core security entities:

1. **SecurityEvent**: Must support 15 mandatory fields: `event_id`, `timestamp`, `source`, `host`, `user`, `event_type`, `severity`, `attack_stage`, `attack_id`, `detection_state`, `investigation_state`, `confidence`, `latency`, `action`, and unparsed `raw_data`.
2. **IOC**: IP, domain, sha256, md5, url, email indicators with confidence score and metadata.
3. **Incident**: Correlated security incident container.
4. **Evidence**: Telemetry-backed evidence items for AI investigation grounding.
5. **TimelineEvent**: Chronological attack timeline milestone entries.
6. **MitreTechnique**: MITRE ATT&CK technique and tactic mapping.
7. **InvestigationResult**: Factual AI investigation findings summary.
8. **RecommendedAction**: Prioritized response and remediation actions.

---

## 💻 Commands to Run the Project

### 1. Backend Setup & Run

```bash
# Navigate to backend directory
cd backend

# Create virtual environment (if not already created)
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
```
- API Health Check: `http://localhost:8000/api/v1/health`
- Swagger OpenAPI Docs: `http://localhost:8000/api/v1/docs`

### 2. Run Backend Tests

```bash
# Run pytest test suite from backend directory
backend/venv/bin/pytest backend/tests
```

### 3. Frontend Setup & Run

```bash
# Navigate to frontend directory
cd frontend

# Install node dependencies
npm install

# Start Vite dev server
npm run dev
```
- Open browser at `http://localhost:5173` to verify frontend connection to backend.

---

## 🧪 Tests Created

- `test_health_check_v1`: Verifies `GET /api/v1/health` returns status `200 OK` with valid health schema payload (`status`, `version`, `app`).
- `test_root_health_check`: Verifies `GET /` returns status `200 OK`.
- `test_security_event_schema_required_fields`: Verifies `SecurityEvent` instantiation and field validations across all 15 required attributes.
- `test_ioc_schema`: Validates `IOC` schema fields and defaults.
- `test_incident_schema`: Validates `Incident` schema and event/IOC ID lists.
- `test_evidence_schema`: Validates `Evidence` schema relevance scores and content dicts.
- `test_timeline_event_schema`: Validates `TimelineEvent` sequence indexing and fields.
- `test_mitre_technique_schema`: Validates `MitreTechnique` mapping fields.
- `test_investigation_result_schema`: Validates `InvestigationResult` confidence scores and evidence linkages.
- `test_recommended_action_schema`: Validates `RecommendedAction` priorities and automation flags.

---

## 📌 Decisions & Assumptions

1. **No Fake AI or Hardcoded Data**: Strict compliance with Phase 1 scope — no mock AI responses or fake incident results were generated.
2. **Database Abstraction Layer**: Implemented a generic `BaseRepository` pattern using SQLAlchemy over SQLite (`sqlite:///./zerotrace.db`), overridable in production via `DATABASE_URL` in `.env`.
3. **Modular Component Interfaces**: Built separate Python package structures for each of the 9 required modules with service interfaces ready for Phase 2+ implementations.
4. **Preservation of Raw Telemetry**: `raw_data` in `SecurityEvent` accepts arbitrary JSON payloads to ensure complete raw log preservation.
5. **CORS & Environment Configuration**: Configured CORS middleware using `pydantic-settings` to allow seamless local development between Vite on port `5173` and FastAPI on port `8000`.
