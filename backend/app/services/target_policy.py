import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit


class TargetPolicyError(ValueError):
    pass


def _validate_ip(address: str) -> None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise TargetPolicyError("The target resolved to an invalid IP address.") from exc

    if (
        not ip.is_global
        or ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise TargetPolicyError(
            "The target resolves to a loopback, private, link-local, multicast, reserved, or otherwise non-public address."
        )


def normalize_target(value: str) -> str:
    try:
        parsed = urlsplit(str(value))
        port = parsed.port
    except ValueError as exc:
        raise TargetPolicyError("The target URL is malformed.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetPolicyError("Only http and https target URLs are supported.")
    if not parsed.hostname or any(char.isspace() for char in parsed.netloc):
        raise TargetPolicyError("The target URL is malformed or has no hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetPolicyError("Embedded credentials are not allowed in target URLs.")
    if port is not None and not 1 <= port <= 65535:
        raise TargetPolicyError("The target URL contains an invalid port.")

    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise TargetPolicyError("Loopback targets are not allowed.")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


async def _resolve(host: str, port: int) -> set[str]:
    loop = asyncio.get_running_loop()
    try:
        records = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetPolicyError("The target hostname could not be resolved.") from exc
    addresses = {record[4][0] for record in records}
    if not addresses:
        raise TargetPolicyError("The target hostname did not resolve to an address.")
    return addresses


async def validate_target(value: str) -> str:
    normalized = normalize_target(value)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    try:
        _validate_ip(host)
    except TargetPolicyError:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise

    addresses = await _resolve(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    for address in addresses:
        _validate_ip(address)
    return normalized


async def validate_redirect(current_url: str, location: str) -> str:
    if not location or "\r" in location or "\n" in location:
        raise TargetPolicyError("The redirect destination is malformed.")
    return await validate_target(urljoin(current_url, location))
