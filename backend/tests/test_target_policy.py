import pytest

from app.services import target_policy


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "https://user:secret@example.com/",
        "not-a-url",
        "http://localhost/",
    ],
)
def test_normalize_target_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(target_policy.TargetPolicyError):
        target_policy.normalize_target(url)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1", "::1", "fc00::1"],
)
@pytest.mark.anyio
async def test_validate_target_rejects_non_public_dns_results(monkeypatch, address: str) -> None:
    async def fake_resolve(host: str, port: int) -> set[str]:
        return {address}

    monkeypatch.setattr(target_policy, "_resolve", fake_resolve)
    with pytest.raises(target_policy.TargetPolicyError, match="non-public"):
        await target_policy.validate_target("https://example.test/")


@pytest.mark.anyio
async def test_redirect_destination_is_fully_revalidated(monkeypatch) -> None:
    async def fake_resolve(host: str, port: int) -> set[str]:
        return {"93.184.216.34"}

    monkeypatch.setattr(target_policy, "_resolve", fake_resolve)
    with pytest.raises(target_policy.TargetPolicyError):
        await target_policy.validate_redirect("https://example.test/", "http://127.0.0.1/admin")


@pytest.mark.anyio
async def test_validate_target_accepts_public_resolution(monkeypatch) -> None:
    async def fake_resolve(host: str, port: int) -> set[str]:
        return {"93.184.216.34"}

    monkeypatch.setattr(target_policy, "_resolve", fake_resolve)
    assert await target_policy.validate_target("HTTPS://Example.Test") == "https://example.test/"
