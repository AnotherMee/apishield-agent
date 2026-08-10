from pathlib import Path
import logging
import os
import tempfile
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from app.agents.graph import build_graph
from app.tools.zap_importer import parse_zap_results
from app.tools.sonarqube_importer import parse_sonarqube_results
from app.tools.finding_correlation import correlate_imported_findings

logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parents[1]
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024)))

app = FastAPI(
    title="APIShield Agent API",
    version="1.0.0",
    description="Passive, specification-based API security review powered by LangGraph.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

def initial_state(spec_path: str, use_ai: bool):
    return {
        "spec_path": spec_path,
        "use_ai": use_ai,
        "endpoints": [],
        "plan": [],
        "planning_mode": "",
        "raw_findings": [],
        "findings": [],
        "timeline": [],
        "report": {},
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan/sample")
def scan_sample(use_ai: bool = False):
    return run_review(BASE_DIR / "examples" / "openapi.yaml", use_ai)


def run_review(path: Path, use_ai: bool) -> dict:
    try:
        result = build_graph().invoke(initial_state(str(path), use_ai))
        return result["report"]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("API review failed")
        raise HTTPException(status_code=500, detail="The API review could not be completed.") from exc

@app.post("/scan/upload")
async def scan_upload(file: UploadFile = File(...), use_ai: bool = Form(False)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".yaml", ".yml", ".json"}:
        raise HTTPException(status_code=400, detail="Please upload an OpenAPI YAML or JSON file.")

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_BYTES // 1024} KB limit.")
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    target: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temporary:
            temporary.write(content)
            target = Path(temporary.name)
        return await run_in_threadpool(run_review, target, use_ai)
    finally:
        if target is not None:
            target.unlink(missing_ok=True)


@app.post("/imports/zap")
async def import_zap(file: UploadFile = File(...)):
    if Path(file.filename or "").suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="Please upload an OWASP ZAP JSON report.")

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_BYTES // 1024} KB limit.")
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    try:
        findings = parse_zap_results(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "source": "OWASP ZAP JSON import",
        "summary": {"total_findings": len(findings), "by_severity": counts},
        "findings": findings,
        "disclaimer": "Imported scanner alerts require manual validation and are not proof of exploitability.",
    }


@app.post("/imports/sonarqube")
async def import_sonarqube(file: UploadFile = File(...)):
    if Path(file.filename or "").suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="Please upload a SonarQube JSON report.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_BYTES // 1024} KB limit.")
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    try:
        findings = parse_sonarqube_results(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _import_report("SonarQube JSON import", findings)


@app.post("/imports/correlate")
async def correlate_imports(
    zap_file: UploadFile = File(...), sonar_file: UploadFile = File(...)
):
    for uploaded, label in ((zap_file, "OWASP ZAP"), (sonar_file, "SonarQube")):
        if Path(uploaded.filename or "").suffix.lower() != ".json":
            raise HTTPException(status_code=400, detail=f"Please upload a {label} JSON report.")

    zap_content = await zap_file.read(MAX_UPLOAD_BYTES + 1)
    sonar_content = await sonar_file.read(MAX_UPLOAD_BYTES + 1)
    await zap_file.close()
    await sonar_file.close()
    if len(zap_content) > MAX_UPLOAD_BYTES or len(sonar_content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Each file must be at most {MAX_UPLOAD_BYTES // 1024} KB.")
    if not zap_content or not sonar_content:
        raise HTTPException(status_code=400, detail="Both imported reports must contain data.")
    try:
        zap_findings = parse_zap_results(zap_content)
        sonar_findings = parse_sonarqube_results(sonar_content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    findings = correlate_imported_findings(zap_findings, sonar_findings)
    report = _import_report("OWASP ZAP and SonarQube correlation", findings)
    report["summary"]["correlated_findings"] = sum(
        1 for finding in findings if finding["status"] == "supported"
    )
    return report


def _import_report(source: str, findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "source": source,
        "summary": {"total_findings": len(findings), "by_severity": counts},
        "findings": findings,
        "disclaimer": "Imported scanner alerts require manual validation and are not proof of exploitability.",
    }
