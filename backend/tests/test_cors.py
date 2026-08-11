from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import configure_cors


def cors_client() -> TestClient:
    application = FastAPI()
    configure_cors(application)

    @application.get("/test")
    def test_endpoint():
        return {"status": "ok"}

    return TestClient(application)


def test_allowed_local_origin_receives_cors_header(monkeypatch) -> None:
    monkeypatch.setenv(
        "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    )
    response = cors_client().get(
        "/test", headers={"Origin": "http://localhost:5173"}
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_production_vercel_origin_can_be_configured(monkeypatch) -> None:
    production_origin = "https://apishield-agent.vercel.app"
    monkeypatch.setenv(
        "ALLOWED_ORIGINS",
        f"http://localhost:5173, http://127.0.0.1:5173, {production_origin}",
    )
    response = cors_client().get("/test", headers={"Origin": production_origin})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == production_origin


def test_disallowed_origin_does_not_receive_cors_header(monkeypatch) -> None:
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:5173")
    response = cors_client().get(
        "/test", headers={"Origin": "https://untrusted.example"}
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_options_preflight_succeeds_for_allowed_origin(monkeypatch) -> None:
    production_origin = "https://apishield-agent.vercel.app"
    monkeypatch.setenv("ALLOWED_ORIGINS", production_origin)
    response = cors_client().options(
        "/test",
        headers={
            "Origin": production_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == production_origin
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "content-type" in response.headers["access-control-allow-headers"].lower()
