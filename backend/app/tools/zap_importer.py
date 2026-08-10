import html
import json
import re
from pathlib import Path
from urllib.parse import urlsplit


RISK_CODE_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
CONFIDENCE_CODE_MAP = {0: 0.2, 1: 0.4, 2: 0.65, 3: 0.85, 4: 0.95}
TAG_PATTERN = re.compile(r"<[^>]+>")
SLUG_PATTERN = re.compile(r"[^a-z0-9]+")


def _plain_text(value: object, fallback: str = "") -> str:
    if value is None:
        return fallback
    text = TAG_PATTERN.sub(" ", str(value))
    return " ".join(html.unescape(text).split()) or fallback


def _integer(value: object, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _severity(alert: dict) -> str:
    if alert.get("riskcode") is not None:
        return RISK_CODE_MAP.get(_integer(alert.get("riskcode")), "info")
    label = str(alert.get("riskdesc", "")).split("(", 1)[0].strip().lower()
    return {"informational": "info", "info": "info"}.get(label, label if label in RISK_CODE_MAP.values() else "info")


def _confidence(alert: dict) -> float:
    value = alert.get("confidence")
    if isinstance(value, str):
        labels = {"false positive": 0.2, "low": 0.4, "medium": 0.65, "high": 0.85, "confirmed": 0.95}
        if value.lower() in labels:
            return labels[value.lower()]
    return CONFIDENCE_CODE_MAP.get(_integer(value, 2), 0.65)


def _endpoint(uri: object) -> str:
    value = str(uri or "unknown")
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        return parsed.path + (f"?{parsed.query}" if parsed.query else "") or "/"
    return value


def _category(alert: dict) -> str:
    name = _plain_text(alert.get("alert") or alert.get("name"), "zap-alert").lower()
    return SLUG_PATTERN.sub("-", name).strip("-") or "zap-alert"


def parse_zap_results(content: bytes | str) -> list[dict]:
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        raise ValueError(f"Could not parse the OWASP ZAP JSON report: {exc}") from exc

    if not isinstance(document, dict) or not isinstance(document.get("site"), list):
        raise ValueError("The JSON file is not an OWASP ZAP report with a site array.")

    findings: list[dict] = []
    for site in document["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts", []), list):
            continue
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances")
            if not isinstance(instances, list) or not instances:
                instances = [{"uri": site.get("@name", "unknown"), "method": "UNKNOWN"}]

            plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or "unknown")
            remediation = _plain_text(
                alert.get("solution"), "Review the imported ZAP alert and define an appropriate defensive control."
            )
            description = _plain_text(alert.get("desc"), "OWASP ZAP reported this condition.")

            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                evidence = [description]
                parameter = _plain_text(instance.get("param"))
                observed = _plain_text(instance.get("evidence") or instance.get("attack"))
                if parameter:
                    evidence.append(f"Parameter: {parameter}")
                if observed:
                    evidence.append(f"Observed evidence: {observed}")

                findings.append(
                    {
                        "id": f"ZAP-{plugin_id}-{len(findings) + 1:03d}",
                        "method": str(instance.get("method") or "UNKNOWN").upper(),
                        "endpoint": _endpoint(instance.get("uri") or site.get("@name")),
                        "category": _category(alert),
                        "severity": _severity(alert),
                        "confidence": _confidence(alert),
                        "evidence": evidence,
                        "source_tools": ["owasp-zap-import"],
                        "remediation": remediation,
                        "status": "imported-needs-review",
                    }
                )

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda finding: severity_order[finding["severity"]], reverse=True)
    return findings


def import_zap_results(path: str | Path) -> list[dict]:
    try:
        return parse_zap_results(Path(path).read_bytes())
    except OSError as exc:
        raise ValueError(f"Could not read the OWASP ZAP JSON report: {exc}") from exc
