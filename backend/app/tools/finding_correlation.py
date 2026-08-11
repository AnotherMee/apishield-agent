import re
from urllib.parse import urlsplit

from app.tools.finding_impacts import potential_impact_for


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TOKEN_PATTERN = re.compile(r"[a-z0-9]{3,}")
STOP_WORDS = {"and", "the", "for", "from", "this", "that", "with", "was", "were", "reported", "review"}
CATEGORY_RULES = {
    "injection": ("injection", "sql", "command", "ldap", "xpath"),
    "cross-site-scripting": ("cross-site", "cross site", "xss", "script"),
    "authentication": ("authentication", "credential", "password", "login"),
    "authorization": ("authorization", "access control", "idor", "permission"),
    "sensitive-data-exposure": ("sensitive", "secret", "disclosure", "exposure", "privacy"),
    "server-side-request-forgery": ("ssrf", "server-side request forgery"),
    "path-traversal": ("path traversal", "directory traversal"),
    "security-header": ("header", "clickjacking", "content security policy", "csp"),
    "cryptography": ("crypto", "cipher", "encryption", "hash"),
}


def normalize_endpoint(value: str) -> str:
    parsed = urlsplit(str(value))
    path = parsed.path if parsed.scheme or parsed.netloc else str(value).split("?", 1)[0]
    if not path or path == "unknown":
        return "unknown"
    segments = []
    for segment in path.rstrip("/").split("/"):
        if re.fullmatch(r"\d+|[0-9a-f]{8}-[0-9a-f-]{27,}", segment, re.IGNORECASE) or (segment.startswith("{") and segment.endswith("}")):
            segments.append("{}")
        else:
            segments.append(segment.lower())
    return "/".join(segments) or "/"


def normalize_category(value: str) -> str:
    text = str(value).lower().replace("-", " ").replace("_", " ")
    for canonical, keywords in CATEGORY_RULES.items():
        if any(keyword in text for keyword in keywords):
            return canonical
    return "-".join(text.split())


def evidence_similarity(left: list[str], right: list[str]) -> float:
    left_tokens = set(TOKEN_PATTERN.findall(" ".join(left).lower())) - STOP_WORDS
    right_tokens = set(TOKEN_PATTERN.findall(" ".join(right).lower())) - STOP_WORDS
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def correlation_score(left: dict, right: dict) -> float:
    endpoint_match = normalize_endpoint(left["endpoint"]) == normalize_endpoint(right["endpoint"])
    if not endpoint_match or normalize_endpoint(left["endpoint"]) == "unknown":
        return 0.0
    methods_match = left["method"] == right["method"] or "UNKNOWN" in {left["method"], right["method"]}
    if not methods_match:
        return 0.0
    category_match = normalize_category(left["category"]) == normalize_category(right["category"])
    similarity = evidence_similarity(left["evidence"], right["evidence"])
    return round(0.5 + (0.35 if category_match else 0.0) + (0.15 * similarity), 4)


def _merge(zap: dict, sonar: dict, index: int) -> dict:
    severity = max((zap["severity"], sonar["severity"]), key=SEVERITY_ORDER.get)
    evidence = list(dict.fromkeys([*zap["evidence"], *sonar["evidence"]]))
    remediations = list(dict.fromkeys([zap["remediation"], sonar["remediation"]]))
    return {
        "id": f"CORR-{index:03d}",
        "method": zap["method"] if zap["method"] != "UNKNOWN" else sonar["method"],
        "endpoint": zap["endpoint"] if zap["endpoint"] != "unknown" else sonar["endpoint"],
        "category": normalize_category(zap["category"]),
        "severity": severity,
        "confidence": round(min(0.97, max(zap["confidence"], sonar["confidence"]) + 0.1), 2),
        "evidence": evidence,
        "source_tools": sorted(set(zap["source_tools"] + sonar["source_tools"])),
        "potential_impact": zap.get("potential_impact") or sonar.get("potential_impact") or potential_impact_for(normalize_category(zap["category"]), severity),
        "remediation": " ".join(remediations),
        "status": "supported",
        "correlation": {
            "source_finding_ids": [zap["id"], sonar["id"]],
            "score": correlation_score(zap, sonar),
        },
    }


def correlate_imported_findings(zap_findings: list[dict], sonar_findings: list[dict]) -> list[dict]:
    candidates = []
    for zap_index, zap in enumerate(zap_findings):
        for sonar_index, sonar in enumerate(sonar_findings):
            score = correlation_score(zap, sonar)
            if score >= 0.86:
                candidates.append((score, zap_index, sonar_index))

    used_zap: set[int] = set()
    used_sonar: set[int] = set()
    correlated = []
    for _, zap_index, sonar_index in sorted(candidates, reverse=True):
        if zap_index in used_zap or sonar_index in used_sonar:
            continue
        used_zap.add(zap_index)
        used_sonar.add(sonar_index)
        correlated.append(_merge(zap_findings[zap_index], sonar_findings[sonar_index], len(correlated) + 1))

    combined = correlated + [finding for index, finding in enumerate(zap_findings) if index not in used_zap]
    combined += [finding for index, finding in enumerate(sonar_findings) if index not in used_sonar]
    combined.sort(key=lambda finding: SEVERITY_ORDER[finding["severity"]], reverse=True)
    return combined
