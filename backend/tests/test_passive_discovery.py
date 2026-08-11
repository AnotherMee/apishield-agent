import httpx
import pytest

from app.services import target_policy
from app.agents.graph import correlate_node, passive_signal_node
from app.services.passive_discovery import OPENAPI_PATHS, SECURITY_TXT_PATH, PassiveDiscoveryLimits, passive_discover


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake_resolve(host: str, port: int) -> set[str]:
        return {"93.184.216.34"}

    monkeypatch.setattr(target_policy, "_resolve", fake_resolve)


@pytest.mark.anyio
async def test_passive_discovery_collects_bounded_response_metadata() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"openapi": "3.1.0", "info": {"title": "Example"}, "paths": {"/users": {}}},
            )
        if request.url.path == SECURITY_TXT_PATH:
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=b"Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00Z\n",
            )
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers=[
                    ("content-type", "application/json"),
                    ("strict-transport-security", "max-age=31536000"),
                    ("access-control-allow-origin", "https://client.example"),
                    ("server", "example-edge"),
                    ("via", "gateway"),
                    ("x-powered-by", "example-framework"),
                    ("set-cookie", "session=secret-value; Secure; HttpOnly; SameSite=Lax"),
                ],
                content=b'{"status":"ok"}',
            )
        return httpx.Response(404, headers={"content-type": "text/plain"}, content=b"not found")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        observations = await passive_discover(
            "https://example.test/",
            client=client,
            limits=PassiveDiscoveryLimits(timeout=1, max_redirects=1, max_response_bytes=4096, max_requests=5),
        )

    by_category = {item.category: item for item in observations}
    assert by_category["http-status"].value == 200
    assert by_category["https-usage"].value is True
    assert by_category["content-type"].value == "application/json"
    assert by_category["server-metadata"].value == {"server": "example-edge", "via": "gateway", "x-powered-by": "example-framework"}
    assert by_category["cookies"].value == [{"name": "session", "secure": True, "httponly": True, "samesite": "Lax"}]
    assert by_category["public-openapi-document"].value["path_count"] == 1
    assert by_category["public-security-txt"].value["has_contact"] is True
    assert "secret-value" not in str(by_category["cookies"].value)
    assert len(requests) == 5


@pytest.mark.anyio
async def test_passive_discovery_uses_only_get_and_allowlisted_paths() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(404, headers={"content-type": "text/plain"}, content=b"no")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await passive_discover(
            "https://example.test/",
            client=client,
            limits=PassiveDiscoveryLimits(timeout=1, max_redirects=1, max_response_bytes=1024, max_requests=5),
        )

    assert all(request.method == "GET" for request in requests)
    assert all(request.content == b"" for request in requests)
    assert {request.url.path for request in requests} == {"/", *OPENAPI_PATHS, SECURITY_TXT_PATH}
    assert not any(request.url.params for request in requests)


@pytest.mark.anyio
async def test_passive_discovery_revalidates_redirects_before_following() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(target_policy.TargetPolicyError):
            await passive_discover(
                "https://example.test/",
                client=client,
                limits=PassiveDiscoveryLimits(timeout=1, max_redirects=2, max_response_bytes=1024, max_requests=3),
            )
    assert len(requests) == 1


async def _finding_categories_for_fixture(headers: list[tuple[str, str]], content: bytes = b'{"ok":true}') -> tuple[set[str], list[dict]]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers=headers, content=content)
        return httpx.Response(404, headers={"content-type": "text/plain"}, content=b"not found")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        observations = await passive_discover(
            "https://fixture.example/",
            client=client,
            limits=PassiveDiscoveryLimits(timeout=1, max_redirects=1, max_response_bytes=4096, max_requests=5),
        )
    state = {
        "observations": [item.model_dump(mode="json") for item in observations],
        "target": "https://fixture.example/",
        "timeline": [],
    }
    signals = passive_signal_node(state)
    correlated = correlate_node({**state, **signals})
    return {item["category"] for item in correlated["findings"]}, correlated["timeline"]


@pytest.mark.anyio
async def test_different_http_fixtures_generate_different_evidence_backed_findings() -> None:
    defensive_headers = [
        ("content-type", "application/json"),
        ("strict-transport-security", "max-age=31536000"),
        ("content-security-policy", "default-src 'none'; frame-ancestors 'none'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "geolocation=()"),
    ]
    weak_headers = [
        ("content-type", "text/html"),
        ("server", "ExampleServer/1.2"),
        ("x-powered-by", "ExampleFramework"),
        ("access-control-allow-origin", "*"),
        ("set-cookie", "session=redacted; Path=/"),
    ]

    defensive_categories, _ = await _finding_categories_for_fixture(defensive_headers)
    weak_categories, _ = await _finding_categories_for_fixture(weak_headers, b"<html><body>Example</body></html>")

    assert "server-metadata-exposure" not in defensive_categories
    assert "permissive-cors" not in defensive_categories
    assert "server-metadata-exposure" in weak_categories
    assert "permissive-cors" in weak_categories
    assert {"cookie-missing-secure", "cookie-missing-httponly", "cookie-missing-samesite"} <= weak_categories
    assert defensive_categories != weak_categories


@pytest.mark.anyio
async def test_two_websites_are_not_forced_into_a_hard_coded_finding_set() -> None:
    json_site, _ = await _finding_categories_for_fixture([
        ("content-type", "application/json"),
        ("strict-transport-security", "max-age=31536000"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ])
    mismatched_site, timeline = await _finding_categories_for_fixture(
        [("content-type", "application/json"), ("cache-control", "public, max-age=3600"), ("set-cookie", "account=redacted; Secure; HttpOnly; SameSite=Lax")],
        b"<html>not json</html>",
    )

    assert "content-type-inconsistency" not in json_site
    assert "content-type-inconsistency" in mismatched_site
    assert "sensitive-response-cache-policy" in mismatched_site
    assert json_site != mismatched_site
    assert "Raw observations:" in timeline[0]["detail"]
    assert "generated signals:" in timeline[0]["detail"]
    assert "final correlated findings:" in timeline[1]["detail"]
