import json
import re
from pathlib import Path


SEVERITY_MAP = {
    "BLOCKER": "critical",
    "CRITICAL": "high",
    "MAJOR": "medium",
    "MINOR": "low",
    "INFO": "info",
}
ENDPOINT_PATTERN = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(/[^\s,;]+)", re.IGNORECASE)
SLUG_PATTERN = re.compile(r"[^a-z0-9]+")


def _endpoint(issue: dict) -> tuple[str, str]:
    explicit = issue.get("endpoint") or issue.get("path")
    method = str(issue.get("method") or "UNKNOWN").upper()
    if explicit:
        return method, str(explicit)

    messages = [str(issue.get("message") or "")]
    for flow in issue.get("flows", []) if isinstance(issue.get("flows"), list) else []:
        if isinstance(flow, dict):
            for location in flow.get("locations", []) if isinstance(flow.get("locations"), list) else []:
                if isinstance(location, dict):
                    messages.append(str(location.get("msg") or location.get("message") or ""))
    match = ENDPOINT_PATTERN.search(" ".join(messages))
    return (match.group(1).upper(), match.group(2)) if match else (method, "unknown")


def _category(issue: dict) -> str:
    rule = str(issue.get("rule") or issue.get("securityCategory") or "sonarqube-issue")
    message = str(issue.get("message") or "")
    value = message if message else rule.split(":")[-1]
    return SLUG_PATTERN.sub("-", value.lower()).strip("-") or "sonarqube-issue"


def _evidence(issue: dict) -> list[str]:
    evidence = []
    message = str(issue.get("message") or "").strip()
    if message:
        evidence.append(message)
    component = str(issue.get("component") or "").strip()
    line = issue.get("line") or (issue.get("textRange") or {}).get("startLine")
    if component:
        location = component + (f":{line}" if line else "")
        evidence.append(f"Static analysis location: {location}")
    return evidence or ["SonarQube reported a security-relevant issue."]


def parse_sonarqube_results(content: bytes | str) -> list[dict]:
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        raise ValueError(f"Could not parse the SonarQube JSON report: {exc}") from exc

    if not isinstance(document, dict):
        raise ValueError("The JSON file is not a SonarQube report object.")
    issues = document.get("issues")
    if issues is None:
        issues = document.get("hotspots")
    if not isinstance(issues, list):
        raise ValueError("The JSON file is not a SonarQube report with an issues or hotspots array.")

    findings = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        method, endpoint = _endpoint(issue)
        severity_label = str(issue.get("severity") or issue.get("vulnerabilityProbability") or "INFO").upper()
        severity = SEVERITY_MAP.get(severity_label, {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(severity_label, "info"))
        rule = str(issue.get("rule") or issue.get("key") or "unknown")
        findings.append(
            {
                "id": f"SONAR-{issue.get('key') or len(findings) + 1}",
                "method": method,
                "endpoint": endpoint,
                "category": _category(issue),
                "severity": severity,
                "confidence": 0.72 if str(issue.get("status", "OPEN")).upper() not in {"CONFIRMED", "REVIEWED"} else 0.85,
                "evidence": _evidence(issue),
                "source_tools": ["sonarqube-import"],
                "remediation": f"Review SonarQube rule {rule} and apply its recommended secure coding remediation.",
                "status": "imported-needs-review",
            }
        )

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda finding: order[finding["severity"]], reverse=True)
    return findings


def import_sonarqube_results(path: str | Path) -> list[dict]:
    try:
        return parse_sonarqube_results(Path(path).read_bytes())
    except OSError as exc:
        raise ValueError(f"Could not read the SonarQube JSON report: {exc}") from exc
