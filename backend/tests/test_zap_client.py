import httpx
import pytest

from app.tools.finding_impacts import potential_impact_for
from app.tools.zap_client import ZapClient, normalize_zap_alerts


@pytest.mark.anyio
async def test_zap_client_runs_scan_and_retrieves_alerts(monkeypatch) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, dict(request.url.params)))
        if request.url.path.endswith("/core/view/version/"):
            return httpx.Response(200, json={"version": "2.15.0"})
        if request.url.path.endswith("/ascan/action/scan/"):
            return httpx.Response(200, json={"scan": "7"})
        if request.url.path.endswith("/ascan/view/status/"):
            return httpx.Response(200, json={"status": "100"})
        if request.url.path.endswith("/core/view/alerts/"):
            return httpx.Response(200, json={"alerts": [{"alert": "SQL Injection", "risk": "High"}]})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = ZapClient("http://zap.test:8080", "test-zap-key", http_client)
        scan_id, alerts = await client.run_authorized_scan("https://api.example.test/")

    assert scan_id == "7"
    assert alerts[0]["alert"] == "SQL Injection"
    assert all(params["apikey"] == "test-zap-key" for _, params in calls)
    assert any(params.get("inScopeOnly") == "true" for _, params in calls)


def test_normalize_zap_alerts_maps_severity_provenance_and_impact() -> None:
    alerts = [{
        "pluginId": "40018",
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "High",
        "url": "https://api.example.test/users?id=1",
        "method": "GET",
        "description": "A SQL injection condition was reported.",
        "evidence": "database error",
        "solution": "Use parameterized queries.",
    }]
    finding = normalize_zap_alerts(alerts, "https://api.example.test/")[0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.85
    assert finding["source_tools"] == ["OWASP ZAP"]
    assert finding["source"] == "OWASP ZAP"
    assert finding["endpoint"] == "/users?id=1"
    assert "could" in finding["potential_impact"]


@pytest.mark.parametrize(
    ("risk", "expected"),
    [("Informational", "info"), ("Low", "low"), ("Medium", "medium"), ("High", "high")],
)
def test_zap_severity_mapping(risk: str, expected: str) -> None:
    finding = normalize_zap_alerts([{"alert": "Example", "risk": risk}], "https://example.test")[0]
    assert finding["severity"] == expected


def test_unknown_category_gets_cautious_deterministic_impact() -> None:
    impact = potential_impact_for("new-passive-observation", "low")
    assert "may" in impact
    assert "could" in impact
