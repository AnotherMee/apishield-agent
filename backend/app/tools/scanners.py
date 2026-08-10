def collect_defensive_signals(endpoints: list[dict]) -> list[dict]:
    findings = []

    for ep in endpoints:
        path = ep["path"].lower()

        if "admin" in path and not ep["auth_required"]:
            findings.append({
                "source": "openapi-review",
                "method": ep["method"],
                "endpoint": ep["path"],
                "category": "missing-authentication",
                "severity": "critical",
                "evidence": "Administrative endpoint has no authentication requirement declared in the OpenAPI metadata.",
            })

        if "{id}" in path:
            findings.append({
                "source": "authorization-review",
                "method": ep["method"],
                "endpoint": ep["path"],
                "category": "object-level-authorization-review",
                "severity": "high",
                "evidence": "Endpoint exposes an object identifier and should be reviewed for per-object authorization enforcement.",
            })

        if ep["method"] in {"POST", "PUT", "PATCH"}:
            findings.append({
                "source": "input-review",
                "method": ep["method"],
                "endpoint": ep["path"],
                "category": "input-validation-review",
                "severity": "medium",
                "evidence": "State-changing endpoint should enforce strict server-side validation and reject unexpected fields.",
            })

        if "search" in path or "query" in path:
            findings.append({
                "source": "data-access-review",
                "method": ep["method"],
                "endpoint": ep["path"],
                "category": "data-access-review",
                "severity": "medium",
                "evidence": "Search/data-access endpoint should use safe parameterized data access and validated input.",
            })

    return findings
