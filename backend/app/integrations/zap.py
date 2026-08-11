from app.models import ActiveScanJob, ActiveScanRequest, Finding, ScannerCapability


class DisabledZapScanner:
    """OWASP ZAP provider placeholder. This class never contacts ZAP or a target."""

    def validate_configuration(self) -> ScannerCapability:
        return ScannerCapability(
            provider="zap",
            configured=False,
            available=False,
            status="disabled",
            detail="OWASP ZAP execution is not implemented in this phase.",
        )

    async def start_scan(self, request: ActiveScanRequest) -> ActiveScanJob:
        capability = self.validate_configuration()
        return ActiveScanJob(
            target=str(request.target),
            provider="zap",
            status="not-configured",
            capability=capability,
            detail=capability.detail,
        )

    async def get_status(self, job_id: str) -> ActiveScanJob:
        raise NotImplementedError("OWASP ZAP execution is disabled.")

    async def get_findings(self, job_id: str) -> list[Finding]:
        return []

    async def cancel_scan(self, job_id: str) -> ActiveScanJob:
        raise NotImplementedError("OWASP ZAP execution is disabled.")
