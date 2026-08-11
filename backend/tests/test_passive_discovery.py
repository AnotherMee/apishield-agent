import httpx
import pytest

from app.services import target_policy
from app.services.passive_discovery import OPENAPI_PATHS, PassiveDiscoveryLimits, passive_discover


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
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/json",
                    "strict-transport-security": "max-age=31536000",
                    "access-control-allow-origin": "https://client.example",
                    "server": "example-edge",
                    "via": "gateway",
                },
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
    assert by_category["server-metadata"].value == {"server": "example-edge", "via": "gateway"}
    assert by_category["public-openapi-document"].value["path_count"] == 1
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
    assert {request.url.path for request in requests} == {"/", *OPENAPI_PATHS}
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
