from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.agents.graph import build_active_graph
from app.models import ActiveScanRequest, AuthorizationAttestation
from app.services.active_scan import request_active_scan, run_active_scan


client = TestClient(app)


def test_active_route_requires_explicit_authorization_acknowledgement() -> None:
    response = client.post(
        "/scans/active",
        json={
            "target": "https://example.test",
            "authorization": {"acknowledged": False, "statement": "I am authorized to test this target."},
        },
    )
    assert response.status_code == 422


def test_active_route_returns_not_configured_without_starting_scan(monkeypatch) -> None:
    monkeypatch.delenv("ZAP_BASE_URL", raising=False)
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    response = client.post(
        "/scans/active",
        json={
            "target": "https://example.test",
            "authorization": {"acknowledged": True, "statement": "I am explicitly authorized to test this target."},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "not-configured"
    assert body["capability"]["available"] is False
    assert "did not contact the target" in body["detail"]
    assert body["findings"] == []


@pytest.mark.anyio
async def test_unconfigured_active_service_never_calls_a_provider(monkeypatch) -> None:
    monkeypatch.delenv("ZAP_BASE_URL", raising=False)
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    request = ActiveScanRequest(
        target="https://example.test",
        authorization=AuthorizationAttestation(
            acknowledged=True,
            statement="I am explicitly authorized to test this target.",
        ),
    )
    job = await request_active_scan(request)
    assert job.status == "not-configured"
    assert job.id is None
    assert job.findings == []


class FakeZapClient:
    configured = True

    def __init__(self, *, reachable=True, fail=False):
        self.reachable = reachable
        self.fail = fail
        self.started = []

    async def check_availability(self):
        return self.reachable

    async def start_authorized_scan(self, target):
        self.started.append(target)
        if self.fail:
            from app.tools.zap_client import ZapScanError
            raise ZapScanError("mock scan failure")
        return "42"

    async def poll_scan_progress(self, scan_id):
        return 100

    async def retrieve_alerts(self, target):
        return [{
            "pluginId": "10020",
            "alert": "Missing Security Header",
            "risk": "Medium",
            "confidence": "High",
            "url": f"{target.rstrip('/')}/users",
            "method": "GET",
            "description": "A defensive header was not present.",
            "solution": "Return the appropriate response header.",
        }]


@pytest.mark.anyio
async def test_authorized_in_scope_scan_completes_with_mocked_zap(monkeypatch) -> None:
    monkeypatch.setenv("ACTIVE_SCAN_APPROVED_ORIGINS", "https://example.test")
    request = ActiveScanRequest(
        target="https://example.test/api",
        authorization=AuthorizationAttestation(
            acknowledged=True,
            statement="I am explicitly authorized to test this target.",
        ),
    )
    client = FakeZapClient()
    job, alerts = await run_active_scan(request, client)
    assert job.status == "completed"
    assert job.progress == 100
    assert job.id == "42"
    assert len(alerts) == 1
    assert client.started == ["https://example.test/api"]


@pytest.mark.anyio
async def test_target_outside_approved_scope_is_rejected_before_scan(monkeypatch) -> None:
    monkeypatch.setenv("ACTIVE_SCAN_APPROVED_ORIGINS", "https://approved.example")
    request = ActiveScanRequest(
        target="https://outside.example/api",
        authorization=AuthorizationAttestation(
            acknowledged=True,
            statement="I am explicitly authorized to test this target.",
        ),
    )
    client = FakeZapClient()
    job, alerts = await run_active_scan(request, client)
    assert job.status == "target-outside-approved-scope"
    assert alerts == []
    assert client.started == []


@pytest.mark.anyio
async def test_zap_failure_returns_failed_status(monkeypatch) -> None:
    monkeypatch.setenv("ACTIVE_SCAN_APPROVED_ORIGINS", "https://example.test")
    request = ActiveScanRequest(
        target="https://example.test",
        authorization=AuthorizationAttestation(
            acknowledged=True,
            statement="I am explicitly authorized to test this target.",
        ),
    )
    job, alerts = await run_active_scan(request, FakeZapClient(fail=True))
    assert job.status == "failed"
    assert "mock scan failure" in job.detail
    assert alerts == []


def test_zap_health_never_exposes_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ZAP_BASE_URL", raising=False)
    monkeypatch.setenv("ZAP_API_KEY", "secret-test-value")
    response = client.get("/health/zap")
    assert response.status_code == 200
    assert response.json() == {"configured": False, "reachable": False}
    assert "secret-test-value" not in response.text


@pytest.mark.anyio
async def test_active_langgraph_normalizes_correlates_and_reports(monkeypatch) -> None:
    monkeypatch.setenv("ACTIVE_SCAN_APPROVED_ORIGINS", "https://example.test")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    request = ActiveScanRequest(
        target="https://example.test/api",
        authorization=AuthorizationAttestation(
            acknowledged=True,
            statement="I am explicitly authorized to test this target.",
        ),
    )
    state = {
        "scan_mode": "authorized_active",
        "target": str(request.target),
        "use_ai": False,
        "active_request": request,
        "zap_client": FakeZapClient(),
        "zap_alerts": [],
        "endpoints": [],
        "observations": [],
        "plan": [],
        "planning_mode": "",
        "planning_fallback_reason": None,
        "raw_findings": [],
        "findings": [],
        "timeline": [],
        "report": {},
    }
    result = await build_active_graph().ainvoke(state)
    job = result["active_job"]
    assert job["status"] == "completed"
    assert job["findings"][0]["source_tools"] == ["OWASP ZAP"]
    assert job["findings"][0]["potential_impact"]
    steps = [item["step"] for item in job["timeline"]]
    assert steps[-5:] == [
        "Run OWASP ZAP",
        "Normalize ZAP Findings",
        "Correlate Findings",
        "Generate Remediation",
        "Generate Report",
    ]
