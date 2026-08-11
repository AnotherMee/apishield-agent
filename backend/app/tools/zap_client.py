import asyncio
import html
import os
import re
from urllib.parse import urlsplit

import httpx

from app.tools.finding_impacts import potential_impact_for


TAG_PATTERN = re.compile(r"<[^>]+>")
SLUG_PATTERN = re.compile(r"[^a-z0-9]+")
SEVERITY_MAP = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
RISK_CODE_MAP = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
CONFIDENCE_MAP = {
    "false positive": 0.2,
    "low": 0.4,
    "medium": 0.65,
    "high": 0.85,
    "confirmed": 0.95,
}


class ZapError(RuntimeError):
    pass


class ZapUnavailableError(ZapError):
    pass


class ZapScanError(ZapError):
    pass


def _plain_text(value: object, fallback: str = "") -> str:
    text = TAG_PATTERN.sub(" ", str(value or ""))
    return " ".join(html.unescape(text).split()) or fallback


def _severity(alert: dict) -> str:
    risk_code = str(alert.get("riskcode", ""))
    if risk_code in RISK_CODE_MAP:
        return RISK_CODE_MAP[risk_code]
    label = str(alert.get("risk") or alert.get("riskdesc") or "info").split("(", 1)[0].strip().lower()
    return SEVERITY_MAP.get(label, "info")


def _confidence(alert: dict) -> float:
    label = str(alert.get("confidence", "medium")).strip().lower()
    if label in CONFIDENCE_MAP:
        return CONFIDENCE_MAP[label]
    codes = {"0": 0.2, "1": 0.4, "2": 0.65, "3": 0.85, "4": 0.95}
    return codes.get(label, 0.65)


def _category(alert: dict) -> str:
    title = _plain_text(alert.get("alert") or alert.get("name"), "zap-alert").lower()
    return SLUG_PATTERN.sub("-", title).strip("-") or "zap-alert"


def _endpoint(alert: dict, target: str) -> str:
    value = str(alert.get("url") or alert.get("uri") or target)
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        return parsed.path + (f"?{parsed.query}" if parsed.query else "") or "/"
    return value


def normalize_zap_alerts(alerts: list[dict], target: str) -> list[dict]:
    findings = []
    for index, alert in enumerate(alerts, start=1):
        if not isinstance(alert, dict):
            continue
        category = _category(alert)
        severity = _severity(alert)
        evidence = [_plain_text(alert.get("description") or alert.get("desc"), "OWASP ZAP reported this condition.")]
        parameter = _plain_text(alert.get("param"))
        observed = _plain_text(alert.get("evidence"))
        if parameter:
            evidence.append(f"Parameter: {parameter}")
        if observed:
            evidence.append(f"Observed evidence: {observed}")
        plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or alert.get("alertRef") or "unknown")
        findings.append({
            "id": f"ZAP-{plugin_id}-{index:03d}",
            "source": "OWASP ZAP",
            "method": str(alert.get("method") or "UNKNOWN").upper(),
            "endpoint": _endpoint(alert, target),
            "category": category,
            "severity": severity,
            "confidence": _confidence(alert),
            "evidence": evidence,
            "source_tools": ["OWASP ZAP"],
            "potential_impact": potential_impact_for(category, severity),
            "remediation": _plain_text(
                alert.get("solution"),
                "Review the OWASP ZAP alert, validate it manually, and apply the appropriate defensive control.",
            ),
            "status": "active-scan-needs-review",
        })
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda finding: order[finding["severity"]], reverse=True)
    return findings


class ZapClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        self.base_url = (base_url if base_url is not None else os.getenv("ZAP_BASE_URL", "")).strip().rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("ZAP_API_KEY", "")
        self._client = client
        self.timeout = max(1.0, float(os.getenv("ZAP_REQUEST_TIMEOUT", "10")))
        self.poll_interval = max(0.1, float(os.getenv("ZAP_POLL_INTERVAL", "1")))
        self.max_polls = max(1, int(os.getenv("ZAP_MAX_POLLS", "300")))

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def _request(self, path: str, params: dict | None = None) -> dict:
        if not self.configured:
            raise ZapUnavailableError("OWASP ZAP is not configured.")
        query = {"apikey": self.api_key, **(params or {})}
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        try:
            response = await client.get(f"{self.base_url}{path}", params=query)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ZapScanError("OWASP ZAP returned an unexpected response.")
            return payload
        except (httpx.HTTPError, ValueError) as exc:
            raise ZapUnavailableError("OWASP ZAP could not be reached or returned an invalid response.") from exc
        finally:
            if owns_client:
                await client.aclose()

    async def check_availability(self) -> bool:
        if not self.configured:
            return False
        try:
            payload = await self._request("/JSON/core/view/version/")
            return bool(payload.get("version"))
        except ZapError:
            return False

    async def start_authorized_scan(self, target: str) -> str:
        payload = await self._request(
            "/JSON/ascan/action/scan/",
            {"url": target, "recurse": "true", "inScopeOnly": "true"},
        )
        scan_id = payload.get("scan")
        if scan_id is None:
            raise ZapScanError("OWASP ZAP did not return a scan identifier.")
        return str(scan_id)

    async def poll_scan_progress(self, scan_id: str) -> int:
        for _ in range(self.max_polls):
            payload = await self._request("/JSON/ascan/view/status/", {"scanId": scan_id})
            try:
                progress = int(payload.get("status", 0))
            except (TypeError, ValueError) as exc:
                raise ZapScanError("OWASP ZAP returned invalid scan progress.") from exc
            if progress >= 100:
                return 100
            await asyncio.sleep(self.poll_interval)
        raise ZapScanError("OWASP ZAP scan did not complete within the configured polling limit.")

    async def retrieve_alerts(self, target: str) -> list[dict]:
        payload = await self._request(
            "/JSON/core/view/alerts/",
            {"baseurl": target, "start": "0", "count": "9999"},
        )
        alerts = payload.get("alerts", [])
        if not isinstance(alerts, list):
            raise ZapScanError("OWASP ZAP returned an invalid alerts collection.")
        return alerts

    async def run_authorized_scan(self, target: str) -> tuple[str, list[dict]]:
        if not await self.check_availability():
            raise ZapUnavailableError("OWASP ZAP is configured but unavailable.")
        scan_id = await self.start_authorized_scan(target)
        await self.poll_scan_progress(scan_id)
        return scan_id, await self.retrieve_alerts(target)
