# APIShield Agent

APIShield is a portfolio-grade, full-stack demonstration of a **passive API security review agent**. It accepts an OpenAPI document, inventories its operations, creates a prioritized review plan, collects explainable metadata-based signals, correlates them, and returns remediation-focused findings.

It does **not** send traffic to described APIs, generate exploit payloads, or perform active vulnerability scanning.

## Architecture

```text
React + TypeScript  ->  FastAPI  ->  LangGraph workflow
                                      | parse
                                      | plan (deterministic or OpenAI-assisted)
                                      | collect passive signals
                                      | correlate
                                      ` report
```

- `frontend/`: responsive React dashboard built with Vite
- `backend/app/main.py`: validated HTTP boundary, upload limits, and CORS configuration
- `backend/app/agents/`: LangGraph orchestration and schema-validated OpenAI planning with deterministic fallback
- `backend/app/tools/`: OpenAPI parsing and passive defensive rules
- `backend/tests/`: API and parser behavior tests

## Local development

Prerequisites: Python 3.11+ and Node.js 20+.

### Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m uvicorn app.main:app --reload --port 8000
```

API documentation is available at `http://127.0.0.1:8000/docs`.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Verification

```powershell
cd backend
.venv\Scripts\python.exe -m pytest

cd ..\frontend
npm run build
```

## Configuration

Copy the provided `.env.example` files when overrides are needed.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENAI_API_KEY` | unset | Enables optional OpenAI-assisted planning |
| `OPENAI_MODEL` | `gpt-5-mini` | Planning model |
| `CORS_ORIGINS` | local Vite origins | Comma-separated browser origins |
| `MAX_UPLOAD_BYTES` | `2097152` | Backend upload limit |
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Browser-facing API URL |

When AI planning is unavailable or fails, the workflow deliberately falls back to its deterministic plan. Both modes return prioritized steps with a priority, title, rationale, and relevant endpoint paths. API keys belong only in the backend environment.

## Security boundaries

- Reviews only OpenAPI YAML/JSON metadata supplied by the user.
- Uses unique temporary files and removes them after each request.
- Rejects unsupported, empty, oversized, malformed, and non-OpenAPI inputs.
- Returns stable client errors without exposing backend exception details.
- Findings are review prompts, not proof of exploitable vulnerabilities.
- Existing OWASP ZAP JSON reports can be imported through `POST /imports/zap`; APIShield never launches ZAP or scans the reported targets.
- SonarQube `issues` and `hotspots` JSON exports can be imported through `POST /imports/sonarqube`.
- `POST /imports/correlate` accepts one ZAP report and one SonarQube report, then correlates normalized findings using endpoint, category, and evidence similarity without contacting either scanner or target.

Only assess systems you own or are explicitly authorized to test.
