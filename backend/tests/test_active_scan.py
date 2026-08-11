from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.models import ActiveScanRequest, AuthorizationAttestation
from app.services.active_scan import request_active_scan


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
    monkeypatch.setenv("ACTIVE_SCAN_PROVIDER", "disabled")
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
    monkeypatch.setenv("ACTIVE_SCAN_PROVIDER", "disabled")
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
