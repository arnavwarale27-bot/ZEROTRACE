# ZEROTRACE - AI Security Investigation Agent for SOC Analysts

ZEROTRACE is a modular, evidence-grounded AI security investigation platform built for SOC analysts. It actively ingests security telemetry, correlates events into structured incidents, extracts IOCs, maps attacker behavior to the MITRE ATT&CK framework, and uses LLMs to synthesize factual, evidence-backed investigation reports and response actions.

---

## 🚀 Features

- **Live Telemetry Ingestion:** Normalizes raw logs (Sysmon, EDR, Network, DNS, Auth) into a unified `SecurityEvent` schema.
- **Automated Incident Correlation:** Groups related security events based on time windows and shared IOCs (hosts, users).
- **MITRE ATT&CK Mapping:** Automatically identifies attacker tactics and techniques from event types.
- **Evidence-Grounded AI Synthesis:** Generates human-readable incident summaries and remediation steps backed strictly by observed telemetry, without hallucinating details.
- **SOC Analyst Console:** An ultra-minimal, typography-driven React/Vite frontend tailored for high-speed triage.

---

## 🏗 Architecture Overview

The system is structured into a FastAPI backend and a Vite+React frontend:

```text
ZEROTRACE/
├── .env                  # Environment configuration (API keys, DB URLs)
├── backend/
│   ├── app/
│   │   ├── main.py       # FastAPI application entrypoint with CORS & API routing
│   │   ├── core/         # Pydantic BaseSettings config & Database sessions
│   │   ├── db/           # SQLite repository abstraction layer
│   │   ├── models/       # Pydantic v2 schemas & SQLAlchemy ORM models
│   │   ├── api/v1/       # REST API Endpoints (Incidents, Events, IOCs, Health)
│   │   └── modules/      # Core Business Logic
│   │       ├── ingestion/     # Log ingest and routing
│   │       ├── normalization/ # Parsing and standardizing logs (DNS, Sysmon, etc.)
│   │       ├── extraction/    # IOC extraction
│   │       ├── correlation/   # Event clustering logic
│   │       ├── mitre/         # Threat intelligence mapping
│   │       └── investigation/ # AI and synthesis engines
│   └── tests/            # Pytest test suite
└── frontend/             # React (Vite) SOC Console
    ├── src/
    │   ├── components/   # UI Modules (Overview, Timeline, AI Investigation, etc.)
    │   ├── services/     # API Axios client
    │   └── index.css     # Minimalist Dark Theme
    └── vite.config.js
```

---

## 💻 Setup & Installation

### 1. Backend Setup & Run

```bash
# Navigate to backend directory
cd backend

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
```
- API Health Check: `http://localhost:8000/api/v1/health`
- Swagger OpenAPI Docs: `http://localhost:8000/api/v1/docs`

### 2. Frontend Setup & Run

```bash
# Navigate to frontend directory
cd frontend

# Install node dependencies
npm install

# Start Vite dev server
npm run dev
```
- Open your browser at `http://localhost:5173` to access the SOC Investigation Console.

---

## 🧪 Testing

Run the pytest test suite from the backend directory:
```bash
backend/venv/bin/pytest backend/tests
```

---

## 🛡️ Minimalist UI Design

The frontend is built for maximum readability and speed. We utilize a strict 3-color palette (Dark Charcoal, Warm Ivory, Amber Accent) and **Inter** typography, avoiding cluttered widgets, gauges, or pie charts in favor of clean, text-driven data presentation.
