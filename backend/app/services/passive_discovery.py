import json
import os
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from app.models import Observation
from app.services.target_policy import validate_redirect, validate_target


SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
CORS_HEADERS = (
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
)
OPENAPI_PATHS = ("/openapi.json", "/swagger.json", "/api/openapi.json")
SECURITY_TXT_PATH = "/.well-known/security.txt"


@dataclass(frozen=True)
class PassiveDiscoveryLimits:
    timeout: float = 8.0
    max_redirects: int = 3
    max_response_bytes: int = 1_000_000
    max_requests: int = 5

    @classmethod
    def from_environment(cls) -> "PassiveDiscoveryLimits":
        return cls(
            timeout=max(0.1, float(os.getenv("PASSIVE_REQUEST_TIMEOUT", "8"))),
            max_redirects=max(0, int(os.getenv("PASSIVE_MAX_REDIRECTS", "3"))),
            max_response_bytes=max(1024, int(os.getenv("PASSIVE_MAX_RESPONSE_BYTES", "1000000"))),
            max_requests=max(1, int(os.getenv("PASSIVE_MAX_REQUESTS", "5"))),
        )


class PassiveDiscoveryError(ValueError):
    pass


async def _read_bounded(response: httpx.Response, limit: int) -> bytes:
    data = bytearray()
    async for chunk in response.aiter_bytes():
        if len(data) + len(chunk) > limit:
            await response.aclose()
            raise PassiveDiscoveryError(f"A target response exceeded the {limit}-byte safety limit.")
        data.extend(chunk)
    await response.aclose()
    return bytes(data)


def _response_observations(
    response: httpx.Response, content: bytes, requested_url: str, redirects: list[dict]
) -> list[Observation]:
    final_url = str(response.url)
    headers = response.headers
    cookies = []
    for header in headers.get_list("set-cookie"):
        parts = [part.strip() for part in header.split(";")]
        attributes = {part.split("=", 1)[0].lower(): part.split("=", 1)[1] if "=" in part else True for part in parts[1:]}
        cookies.append({
            "name": parts[0].split("=", 1)[0],
            "secure": "secure" in attributes,
            "httponly": "httponly" in attributes,
            "samesite": attributes.get("samesite"),
        })

    declared_type = headers.get("content-type", "")
    lowered = content[:512].lstrip().lower()
    detected_type = "empty"
    if lowered.startswith((b"{", b"[")):
        detected_type = "json-like"
    elif lowered.startswith((b"<!doctype html", b"<html")):
        detected_type = "html-like"
    elif lowered:
        detected_type = "text-or-binary"
    declared_lower = declared_type.lower()
    consistent = not (
        ("json" in declared_lower and detected_type not in {"json-like", "empty"})
        or ("html" in declared_lower and detected_type not in {"html-like", "empty"})
        or (detected_type == "html-like" and "html" not in declared_lower)
        or (detected_type == "json-like" and declared_type and "json" not in declared_lower)
    )

    requested_scheme = urlsplit(requested_url).scheme
    downgrade = any(urlsplit(item["from"]).scheme == "https" and urlsplit(item["to"]).scheme == "http" for item in redirects)
    path = response.url.path.lower()
    potentially_sensitive = bool(cookies) or any(token in path for token in ("login", "account", "profile", "admin", "token", "user"))

    return [
        Observation(category="http-status", url=final_url, value=response.status_code),
        Observation(category="final-url", url=final_url, value=final_url),
        Observation(category="https-usage", url=final_url, value=response.url.scheme == "https"),
        Observation(
            category="redirects",
            url=final_url,
            value=redirects,
            metadata={"requested_url": requested_url, "count": len(redirects)},
        ),
        Observation(
            category="https-redirect-behavior",
            url=final_url,
            value={
                "requested_scheme": requested_scheme,
                "final_scheme": response.url.scheme,
                "upgraded": requested_scheme == "http" and response.url.scheme == "https",
                "downgrade_observed": downgrade,
            },
            metadata={"redirect_count": len(redirects)},
        ),
        Observation(
            category="security-headers",
            url=final_url,
            value={name: headers[name] for name in SECURITY_HEADERS if name in headers},
            metadata={"checked": list(SECURITY_HEADERS)},
        ),
        Observation(
            category="cors-headers",
            url=final_url,
            value={name: headers[name] for name in CORS_HEADERS if name in headers},
            metadata={"checked": list(CORS_HEADERS)},
        ),
        Observation(category="content-type", url=final_url, value=declared_type),
        Observation(
            category="content-type-consistency",
            url=final_url,
            value={"declared": declared_type, "detected": detected_type, "consistent": consistent},
        ),
        Observation(category="response-size", url=final_url, value=len(content), metadata={"unit": "bytes"}),
        Observation(
            category="server-metadata",
            url=final_url,
            value={name: headers[name] for name in ("server", "via", "x-powered-by") if name in headers},
        ),
        Observation(category="cookies", url=final_url, value=cookies, metadata={"count": len(cookies)}),
        Observation(
            category="cache-policy",
            url=final_url,
            value={
                "cache-control": headers.get("cache-control", ""),
                "pragma": headers.get("pragma", ""),
                "expires": headers.get("expires", ""),
                "potentially_sensitive": potentially_sensitive,
            },
        ),
    ]


def _openapi_observation(response: httpx.Response, content: bytes) -> Observation | None:
    if "json" not in response.headers.get("content-type", "").lower():
        return None
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(document, dict) or not (document.get("openapi") or document.get("swagger")):
        return None
    paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
    return Observation(
        category="public-openapi-document",
        url=str(response.url),
        value={
            "version": document.get("openapi") or document.get("swagger"),
            "title": (document.get("info") or {}).get("title") if isinstance(document.get("info"), dict) else None,
            "path_count": len(paths),
            "paths": list(paths)[:100],
        },
        metadata={"discovery": "conventional-allowlisted-path"},
    )


def _security_txt_observation(response: httpx.Response, content: bytes) -> Observation | None:
    if response.status_code != 200 or not content:
        return None
    content_type = response.headers.get("content-type", "").lower()
    if content_type and not any(value in content_type for value in ("text/plain", "text/", "application/octet-stream")):
        return None
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    fields = {
        line.split(":", 1)[0].strip().lower()
        for line in text.splitlines()
        if ":" in line and not line.lstrip().startswith("#")
    }
    if "contact" not in fields:
        return None
    return Observation(
        category="public-security-txt",
        url=str(response.url),
        value={"has_contact": True, "has_expires": "expires" in fields, "fields": sorted(fields)},
        metadata={"discovery": "well-known-standard-path", "response_size": len(content)},
    )


async def passive_discover(
    target: str,
    *,
    client: httpx.AsyncClient | None = None,
    limits: PassiveDiscoveryLimits | None = None,
) -> list[Observation]:
    limits = limits or PassiveDiscoveryLimits.from_environment()
    start_url = await validate_target(target)
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=limits.timeout, follow_redirects=False)

    request_count = 0

    async def get(url: str) -> tuple[httpx.Response, bytes, list[dict]]:
        nonlocal request_count
        current = await validate_target(url)
        redirects: list[dict] = []
        while True:
            if request_count >= limits.max_requests:
                raise PassiveDiscoveryError("The passive discovery request limit was reached.")
            request_count += 1
            request = client.build_request(
                "GET",
                current,
                headers={"Accept": "application/json, text/html;q=0.8, */*;q=0.1", "User-Agent": "APIShield-Passive-Discovery/1.0"},
            )
            response = await client.send(request, stream=True, follow_redirects=False)
            content = await _read_bounded(response, limits.max_response_bytes)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response, content, redirects
            if len(redirects) >= limits.max_redirects:
                raise PassiveDiscoveryError("The target exceeded the passive discovery redirect limit.")
            destination = await validate_redirect(current, response.headers.get("location", ""))
            redirects.append({"status": response.status_code, "from": current, "to": destination})
            current = destination

    try:
        root_response, root_content, redirects = await get(start_url)
        observations = _response_observations(root_response, root_content, start_url, redirects)

        final = urlsplit(str(root_response.url))
        origin = f"{final.scheme}://{final.netloc}"
        existing_path = final.path.rstrip("/") or "/"
        for path in OPENAPI_PATHS:
            if request_count >= limits.max_requests:
                break
            if existing_path == path:
                candidate_response, candidate_content = root_response, root_content
            else:
                candidate_response, candidate_content, _ = await get(urljoin(origin, path))
            observation = _openapi_observation(candidate_response, candidate_content)
            if observation is not None:
                observations.append(observation)
        if request_count < limits.max_requests:
            security_response, security_content, _ = await get(urljoin(origin, SECURITY_TXT_PATH))
            security_observation = _security_txt_observation(security_response, security_content)
            if security_observation is not None:
                observations.append(security_observation)
        return observations
    except httpx.HTTPError as exc:
        raise PassiveDiscoveryError(f"The passive request failed: {exc}") from exc
    finally:
        if owns_client:
            await client.aclose()
