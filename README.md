# APIShield Agent

APIShield is a portfolio-grade, full-stack demonstration of a **passive API security review agent**. It reviews a public URL or an OpenAPI document, creates a prioritized plan, collects explainable security signals, correlates findings, and returns remediation-focused guidance.

It does **not** send traffic to described APIs, generate exploit payloads, or perform active vulnerability scanning.

## Architecture

```text
React -> FastAPI -> LangGraph -> Passive URL/OpenAPI analysis
                              -> Finding correlation
                              -> OpenAI-assisted planning/remediation
                              -> Report
```

- `frontend/`: responsive React dashboard built with Vite
- `backend/app/main.py`: validated HTTP boundary, upload limits, and CORS configuration
- `backend/app/agents/`: LangGraph orchestration and schema-validated OpenAI planning with deterministic fallback
- `backend/app/tools/`: OpenAPI parsing and passive defensive rules
- `backend/tests/`: API and parser behavior tests
- `dotnet/`: typed C# client, ASP.NET Core interoperability gateway, and xUnit contract tests

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
| `ALLOWED_ORIGINS` | local Vite origins | Comma-separated browser origins |
| `PASSIVE_REQUEST_TIMEOUT` | `8` | Per-request timeout for passive URL review |
| `PASSIVE_MAX_REDIRECTS` | `3` | Maximum validated redirect hops |
| `PASSIVE_MAX_RESPONSE_BYTES` | `1000000` | Maximum bytes read per response |
| `PASSIVE_MAX_REQUESTS` | `5` | Maximum ordinary requests per URL review |
| `MAX_UPLOAD_BYTES` | `2097152` | Backend upload limit |
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Browser-facing API URL |

When AI planning is unavailable or fails, the workflow deliberately falls back to its deterministic plan. Both modes return prioritized steps with a priority, title, rationale, and relevant endpoint paths. API keys belong only in the backend environment.

## Security boundaries

- Reviews supplied OpenAPI YAML/JSON metadata or public URL response metadata.
- Resolves targets before requests and rejects unsafe address ranges, embedded credentials, unsupported schemes, and unsafe redirect destinations.
- Uses unique temporary files and removes them after each request.
- Rejects unsupported, empty, oversized, malformed, and non-OpenAPI inputs.
- Returns stable client errors without exposing backend exception details.
- Findings are review prompts, not proof of exploitable vulnerabilities.
- Existing OWASP ZAP JSON reports can be imported through `POST /imports/zap`; APIShield never launches ZAP or scans the reported targets.
- SonarQube `issues` and `hotspots` JSON exports can be imported through `POST /imports/sonarqube`.
- `POST /imports/correlate` accepts one ZAP report and one SonarQube report, then correlates normalized findings using endpoint, category, and evidence similarity without contacting either scanner or target.

Use APIShield for defensive review of public endpoints and API specifications you are permitted to assess.

## .NET Integration

The .NET layer demonstrates production-style interoperability without duplicating APIShield's security engine. The Python/FastAPI service remains authoritative for target validation, SSRF controls, passive HTTP analysis, LangGraph orchestration, OpenAI-assisted planning, findings, remediation, and reporting.

```text
.NET caller
  -> APIShield.Gateway (ASP.NET Core)
  -> APIShield.Client (typed HttpClient)
  -> existing FastAPI backend
  -> LangGraph / passive analysis / report
```

### Projects

- `APIShield.Client`: reusable asynchronous client using an injected `HttpClient`, `System.Net.Http.Json`, `System.Text.Json`, strongly typed records, and `CancellationToken`.
- `APIShield.Gateway`: small ASP.NET Core Web API exposing `GET /health` and `POST /api/security/analyze-url`. It consumes the client library and never calls OpenAI directly.
- `APIShield.Tests`: xUnit client, contract-fixture, and `WebApplicationFactory` gateway tests. Tests use in-memory fakes and do not contact external targets or OpenAI.

The C# `PassiveDiscoveryRequest` corresponds to Python's `PassiveDiscoveryRequest`. `ScanReport`, `Observation`, `Finding`, `ReviewStep`, `TimelineItem`, `ToolInvocation`, and `RemediationItem` correspond to the Pydantic/report structures returned by `POST /discovery/passive`. Flexible Python `Any` and correlation fields are represented with `JsonElement` dictionaries so unknown observation metadata is preserved.

### Requirements and configuration

.NET SDK 10.0 or later in the .NET 10 release line is required. Confirm the installed SDK:

```powershell
dotnet --version
```

The gateway reads `APISHIELD_BACKEND_URL`. It defaults safely to `http://127.0.0.1:8000/` for local development. Do not place OpenAI credentials or other backend secrets in the gateway; OpenAI remains configured only in FastAPI.

```powershell
$env:APISHIELD_BACKEND_URL = "http://127.0.0.1:8000/"
```

### Build and test

From the repository root:

```powershell
dotnet restore dotnet/APIShield.sln
dotnet build dotnet/APIShield.sln
dotnet test dotnet/APIShield.sln
```

The tests deserialize `dotnet/APIShield.Tests/Fixtures/passive-scan-report.json`, a representative fixture based on the real FastAPI `ScanReport` contract. This provides lightweight cross-language contract-drift protection without introducing schema-generation infrastructure.

### Run locally

Start FastAPI in one terminal:

```powershell
cd backend
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Start the gateway in another terminal:

```powershell
$env:APISHIELD_BACKEND_URL = "http://127.0.0.1:8000/"
dotnet run --project dotnet/APIShield.Gateway --urls http://127.0.0.1:5080
```

Check both services through the gateway:

```powershell
Invoke-RestMethod http://127.0.0.1:5080/health
```

Run a passive review through ASP.NET Core and FastAPI:

```powershell
$body = @{ target = "https://example.com/"; use_ai = $false } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:5080/api/security/analyze-url `
  -Method Post -ContentType "application/json" -Body $body
```

The gateway does not add scanning behavior or bypass FastAPI's public-target and redirect validation. Only use the review endpoint for public targets you are permitted to assess.
