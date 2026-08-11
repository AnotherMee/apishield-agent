import os
from urllib.parse import urlsplit

from app.integrations.active_scanner import ActiveScanner
from app.models import ActiveScanJob, ActiveScanRequest, ScannerCapability
from app.services.target_policy import normalize_target
from app.tools.zap_client import ZapClient, ZapError, ZapUnavailableError


def _origin(value: str) -> str:
    normalized = normalize_target(value)
    parsed = urlsplit(normalized)
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    suffix = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname}{suffix}"


def approved_active_origins() -> set[str]:
    configured = os.getenv("ACTIVE_SCAN_APPROVED_ORIGINS", "")
    origins = set()
    for value in configured.split(","):
        if value.strip():
            try:
                origins.add(_origin(value.strip()))
            except ValueError:
                continue
    return origins


def target_is_approved(target: str) -> bool:
    try:
        return _origin(target) in approved_active_origins()
    except ValueError:
        return False


def active_scan_capability(client: ActiveScanner | None = None) -> ScannerCapability:
    zap = client or ZapClient()
    if not zap.configured:
        return ScannerCapability(
            provider="zap",
            configured=False,
            available=False,
            status="not-configured",
            detail="OWASP ZAP is not configured. APIShield did not contact the target.",
        )
    return ScannerCapability(
        provider="zap",
        configured=True,
        available=False,
        status="unavailable",
        detail="OWASP ZAP is configured; availability has not yet been verified.",
    )


async def zap_health_status(client: ActiveScanner | None = None) -> dict[str, bool]:
    zap = client or ZapClient()
    return {"configured": zap.configured, "reachable": await zap.check_availability() if zap.configured else False}


async def run_active_scan(
    request: ActiveScanRequest, client: ActiveScanner | None = None
) -> tuple[ActiveScanJob, list[dict]]:
    target = str(request.target)
    zap = client or ZapClient()
    capability = active_scan_capability(zap)

    if not request.authorization.acknowledged:
        return ActiveScanJob(
            target=target,
            provider="zap",
            status="authorization-required",
            capability=capability,
            detail="Explicit authorization acknowledgement is required. No active scan was started.",
        ), []

    if not zap.configured:
        return ActiveScanJob(
            target=target,
            provider="zap",
            status="not-configured",
            capability=capability,
            detail=capability.detail,
        ), []

    if not target_is_approved(target):
        return ActiveScanJob(
            target=target,
            provider="zap",
            status="target-outside-approved-scope",
            capability=capability,
            detail="The target is outside the backend-approved active-scan scope. No active scan was started.",
        ), []

    reachable = await zap.check_availability()
    if not reachable:
        unavailable = ScannerCapability(
            provider="zap",
            configured=True,
            available=False,
            status="unavailable",
            detail="OWASP ZAP is configured but unavailable. No active scan was started.",
        )
        return ActiveScanJob(
            target=target,
            provider="zap",
            status="zap-unavailable",
            capability=unavailable,
            detail=unavailable.detail,
        ), []

    ready = ScannerCapability(
        provider="zap",
        configured=True,
        available=True,
        status="ready",
        detail="OWASP ZAP is configured and reachable.",
    )
    try:
        scan_id = await zap.start_authorized_scan(target)
        await zap.poll_scan_progress(scan_id)
        alerts = await zap.retrieve_alerts(target)
    except ZapUnavailableError:
        unavailable = ready.model_copy(update={"available": False, "status": "unavailable", "detail": "OWASP ZAP became unavailable during the scan."})
        return ActiveScanJob(
            target=target,
            provider="zap",
            status="zap-unavailable",
            capability=unavailable,
            detail=unavailable.detail,
        ), []
    except ZapError as exc:
        return ActiveScanJob(
            target=target,
            provider="zap",
            status="failed",
            capability=ready,
            detail=f"OWASP ZAP scan failed: {exc}",
        ), []

    return ActiveScanJob(
        id=scan_id,
        target=target,
        provider="zap",
        status="completed",
        capability=ready,
        detail=f"OWASP ZAP completed the authorized scan and returned {len(alerts)} alerts.",
        progress=100,
    ), alerts


async def request_active_scan(request: ActiveScanRequest, provider=None) -> ActiveScanJob:
    """Compatibility facade for callers that only need job status."""
    job, _ = await run_active_scan(request, provider)
    return job
