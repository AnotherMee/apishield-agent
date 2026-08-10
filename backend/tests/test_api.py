from fastapi.testclient import TestClient
import json

from app.main import app
from app.tools.openapi_parser import inventory


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_sample_review_is_deterministic() -> None:
    response = client.post("/scan/sample?use_ai=false")
    report = response.json()
    assert response.status_code == 200
    assert report["endpoint_count"] == 4
    assert report["planning_mode"] == "Deterministic"
    assert report["summary"]["total_findings"] == 4
    assert len(report["timeline"]) == 5
    assert [event["node"] for event in report["timeline"]] == ["parse", "plan", "scan", "correlate", "report"]
    assert report["timeline"][0]["tool_invocations"][0]["name"] == "openapi_parser.inventory"
    assert len(report["remediation_report"]) == 4


def test_upload_rejects_invalid_extension() -> None:
    response = client.post("/scan/upload", files={"file": ("spec.txt", b"hello", "text/plain")})
    assert response.status_code == 400


def test_upload_rejects_invalid_openapi() -> None:
    response = client.post("/scan/upload", files={"file": ("spec.yaml", b"hello: world", "text/yaml")})
    assert response.status_code == 422
    assert "OpenAPI" in response.json()["detail"]


def test_operation_can_override_global_security() -> None:
    spec = {
        "openapi": "3.0.3",
        "security": [{"bearer": []}],
        "paths": {
            "/public": {"get": {"security": []}},
            "/private": {"get": {}},
        },
    }
    endpoints = inventory(spec)
    assert [endpoint["auth_required"] for endpoint in endpoints] == [False, True]


def test_zap_import_endpoint_returns_normalized_findings() -> None:
    report = {
        "site": [{"@name": "https://example.test", "alerts": [{
            "pluginid": "1", "alert": "Example Alert", "riskcode": "3",
            "confidence": "2", "instances": [{"uri": "https://example.test/api", "method": "GET"}],
        }]}]
    }
    response = client.post(
        "/imports/zap",
        files={"file": ("zap.json", json.dumps(report).encode(), "application/json")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["summary"] == {"total_findings": 1, "by_severity": {"high": 1}}
    assert body["findings"][0]["source_tools"] == ["owasp-zap-import"]


def test_zap_import_endpoint_rejects_non_zap_json() -> None:
    response = client.post(
        "/imports/zap", files={"file": ("report.json", b"{}", "application/json")}
    )
    assert response.status_code == 422


def test_correlation_endpoint_merges_supported_findings() -> None:
    zap = {
        "site": [{"alerts": [{
            "pluginid": "40018", "alert": "SQL Injection", "riskcode": "3", "confidence": "3",
            "desc": "SQL injection from user input", "instances": [{"uri": "https://example.test/users/42", "method": "GET"}],
        }]}]
    }
    sonar = {
        "issues": [{
            "key": "issue-1", "rule": "python:S3649", "severity": "CRITICAL",
            "message": "SQL injection from unparameterized user input in GET /users/{id}",
        }]
    }
    response = client.post(
        "/imports/correlate",
        files={
            "zap_file": ("zap.json", json.dumps(zap).encode(), "application/json"),
            "sonar_file": ("sonar.json", json.dumps(sonar).encode(), "application/json"),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["total_findings"] == 1
    assert body["summary"]["correlated_findings"] == 1
    assert body["findings"][0]["status"] == "supported"
