import os

from app.integrations.active_scanner import ActiveScanner
from app.models import ActiveScanJob, ActiveScanRequest, ScannerCapability


def active_scan_capability() -> ScannerCapability:
    configured = os.getenv("ACTIVE_SCAN_PROVIDER", "disabled").strip().lower()
    detail = (
        "No active scanning provider is configured. APIShield did not contact the target."
        if configured in {"", "disabled", "none"}
        else f"Active provider '{configured}' is not implemented. APIShield did not contact the target."
    )
    return ScannerCapability(
        provider=configured or "disabled",
        configured=False,
        available=False,
        status="not-configured",
        detail=detail,
    )


async def request_active_scan(
    request: ActiveScanRequest, provider: ActiveScanner | None = None
) -> ActiveScanJob:
    # Pydantic requires acknowledged=True before this function can be reached.
    if provider is None:
        capability = active_scan_capability()
        return ActiveScanJob(
            target=str(request.target),
            provider=capability.provider,
            status="not-configured",
            capability=capability,
            detail=capability.detail,
        )
    capability = provider.validate_configuration()
    if not capability.available or not capability.configured:
        return ActiveScanJob(
            target=str(request.target),
            provider=capability.provider,
            status="not-configured",
            capability=capability,
            detail=capability.detail,
        )
    return await provider.start_scan(request)
