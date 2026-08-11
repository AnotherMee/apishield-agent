from collections import defaultdict
from langgraph.graph import StateGraph, START, END
from typing import TypedDict

from app.tools.openapi_parser import load_spec, inventory
from app.tools.scanners import collect_defensive_signals
from app.agents.planner import create_plan
from app.models import ScanMode
from app.tools.finding_impacts import potential_impact_for

class State(TypedDict, total=False):
    spec_path: str
    use_ai: bool
    scan_mode: str
    target: str | None
    endpoints: list[dict]
    observations: list[dict]
    plan: list[dict]
    planning_mode: str
    planning_fallback_reason: str | None
    raw_findings: list[dict]
    findings: list[dict]
    timeline: list[dict]
    report: dict

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

REMEDIATION = {
    "missing-authentication": "Require authentication and explicit server-side authorization for administrative routes.",
    "object-level-authorization-review": "Enforce object-level authorization on every request using the authenticated principal.",
    "input-validation-review": "Validate input server-side against a strict schema and reject unexpected fields.",
    "data-access-review": "Use safe parameterized data-access APIs and validate untrusted input before processing.",
}

def add_event(
    state: State,
    node: str,
    step: str,
    detail: str,
    tool: str,
    tool_summary: str,
):
    timeline = list(state["timeline"])
    timeline.append({
        "node": node,
        "step": step,
        "detail": detail,
        "status": "completed",
        "tool_invocations": [{
            "name": tool,
            "status": "completed",
            "summary": tool_summary,
        }],
    })
    return timeline

def parse_node(state: State):
    endpoints = inventory(load_spec(state["spec_path"]))
    return {
        "endpoints": endpoints,
        "timeline": add_event(
            state, "parse", "Parse OpenAPI", f"Discovered {len(endpoints)} endpoints",
            "openapi_parser.inventory", f"Loaded the specification and normalized {len(endpoints)} operations.",
        ),
    }

def plan_node(state: State):
    plan, mode, fallback_reason = create_plan(state["endpoints"], state["use_ai"])
    detail = f"Generated {len(plan)} prioritized steps using {mode} planning"
    tool_summary = f"Produced a schema-validated {mode.lower()} defensive review plan."
    if fallback_reason:
        detail += f" (fallback: {fallback_reason})"
        tool_summary += f" Fallback reason: {fallback_reason}."
    return {
        "plan": plan,
        "planning_mode": mode,
        "planning_fallback_reason": fallback_reason,
        "timeline": add_event(
            state, "plan", "Plan Review", detail,
            "planner.create_plan", tool_summary,
        ),
    }

def scan_node(state: State):
    findings = collect_defensive_signals(state["endpoints"])
    return {
        "raw_findings": findings,
        "timeline": add_event(
            state, "scan", "Collect Security Signals", f"Collected {len(findings)} defensive review signals",
            "scanners.collect_defensive_signals", f"Applied passive metadata rules to {len(state['endpoints'])} endpoints.",
        ),
    }


def passive_signal_node(state: State):
    observations = state.get("observations", [])
    by_category = {item["category"]: item for item in observations}
    target = state.get("target") or "unknown"
    findings = []

    def add(category: str, severity: str, evidence: str, remediation: str, observation: dict):
        findings.append({
            "source": "passive-http",
            "method": "GET",
            "endpoint": observation.get("url") or target,
            "category": category,
            "severity": severity,
            "evidence": evidence,
            "remediation": remediation,
        })

    https = by_category.get("https-usage")
    if https and not https["value"]:
        add("insecure-transport", "medium", "The final response was served over HTTP rather than HTTPS.",
            "Serve the API over HTTPS and redirect HTTP traffic to HTTPS.", https)

    security = by_category.get("security-headers")
    if security:
        present = security["value"]
        header_checks = {
            "content-security-policy": (
                "missing-content-security-policy", "The response did not include Content-Security-Policy.",
                "Define a Content-Security-Policy appropriate to the response content and application context.",
            ),
            "x-content-type-options": (
                "missing-x-content-type-options", "The response did not include X-Content-Type-Options.",
                "Return X-Content-Type-Options: nosniff where browser content-type sniffing is not required.",
            ),
            "referrer-policy": (
                "missing-referrer-policy", "The response did not include Referrer-Policy.",
                "Set a Referrer-Policy that limits unnecessary URL information sent to other origins.",
            ),
            "permissions-policy": (
                "missing-permissions-policy", "The response did not include Permissions-Policy.",
                "Define a Permissions-Policy for browser features relevant to the application.",
            ),
        }
        for header, (category, evidence, remediation) in header_checks.items():
            if header not in present:
                add(category, "low", evidence, remediation, security)

        if https and https["value"] and "strict-transport-security" not in present:
            add("missing-strict-transport-security", "low",
                "The HTTPS response did not include Strict-Transport-Security.",
                "Return a carefully scoped Strict-Transport-Security policy after confirming HTTPS coverage.", security)

        csp = str(present.get("content-security-policy", "")).lower()
        if "x-frame-options" not in present and "frame-ancestors" not in csp:
            add("missing-framing-protection", "low",
                "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive was observed.",
                "Use CSP frame-ancestors or X-Frame-Options to define whether browser framing is permitted.", security)

    cors = by_category.get("cors-headers")
    if cors:
        values = cors["value"]
        origin = values.get("access-control-allow-origin", "").strip().lower()
        credentials = values.get("access-control-allow-credentials", "").lower() == "true"
        methods = values.get("access-control-allow-methods", "")
        if origin in {"*", "null"}:
            add("permissive-cors", "high" if credentials else "medium",
                f"The ordinary response declared Access-Control-Allow-Origin: {origin}." + (" Access-Control-Allow-Credentials was also true." if credentials else ""),
                "Restrict CORS response headers to explicitly trusted origins and avoid broad credentialed policies.", cors)
        if "*" in methods:
            add("permissive-cors-methods", "medium",
                f"The response declared a wildcard Access-Control-Allow-Methods policy: {methods}.",
                "List only the cross-origin HTTP methods required by trusted browser clients.", cors)

    metadata = by_category.get("server-metadata")
    if metadata and metadata["value"]:
        add("server-metadata-exposure", "info", f"The response exposed server or framework metadata: {metadata['value']}.",
            "Minimize unnecessary product, framework, and intermediary disclosure in response headers.", metadata)

    cookies = by_category.get("cookies")
    if cookies and cookies["value"]:
        missing_secure = [item["name"] for item in cookies["value"] if not item["secure"]]
        missing_httponly = [item["name"] for item in cookies["value"] if not item["httponly"]]
        missing_samesite = [item["name"] for item in cookies["value"] if not item["samesite"]]
        if missing_secure:
            add("cookie-missing-secure", "medium", f"Cookies without the Secure attribute were observed: {', '.join(missing_secure)}.",
                "Apply Secure to cookies that should only be sent over HTTPS.", cookies)
        if missing_httponly:
            add("cookie-missing-httponly", "low", f"Cookies without the HttpOnly attribute were observed: {', '.join(missing_httponly)}.",
                "Apply HttpOnly to cookies that do not require client-side script access.", cookies)
        if missing_samesite:
            add("cookie-missing-samesite", "low", f"Cookies without a SameSite attribute were observed: {', '.join(missing_samesite)}.",
                "Set an explicit SameSite policy that matches the application's cross-site requirements.", cookies)

    redirect = by_category.get("https-redirect-behavior")
    if redirect:
        behavior = redirect["value"]
        if behavior.get("downgrade_observed"):
            add("https-redirect-downgrade", "medium", "A redirect from an HTTPS URL to an HTTP URL was observed.",
                "Keep redirect destinations on HTTPS and remove transport downgrade paths.", redirect)
        elif behavior.get("requested_scheme") == "http" and not behavior.get("upgraded"):
            add("missing-https-redirect", "low", "An HTTP request did not upgrade to HTTPS through the observed redirect chain.",
                "Redirect public HTTP entry points to their HTTPS equivalents.", redirect)

    cache = by_category.get("cache-policy")
    if cache and cache["value"].get("potentially_sensitive"):
        cache_control = str(cache["value"].get("cache-control", "")).lower()
        if "public" in cache_control or not any(directive in cache_control for directive in ("no-store", "private")):
            add("sensitive-response-cache-policy", "low",
                f"A response with potentially sensitive indicators used Cache-Control: {cache_control or '(not present)' }.",
                "Review whether the response can contain user-specific data and apply private or no-store where caching is inappropriate.", cache)

    content_type = by_category.get("content-type-consistency")
    if content_type and not content_type["value"].get("consistent"):
        value = content_type["value"]
        add("content-type-inconsistency", "low",
            f"The declared content type '{value.get('declared') or '(not present)'}' did not match the observed {value.get('detected')} response shape.",
            "Return an accurate Content-Type header and use X-Content-Type-Options: nosniff where appropriate.", content_type)

    for observation in observations:
        if observation["category"] == "public-openapi-document":
            add("public-api-metadata", "info", f"A public API description was available at {observation['url']}.",
                "Confirm that public API metadata is intentional and does not disclose internal-only operations.", observation)
        elif observation["category"] == "public-security-txt":
            add("public-security-contact-metadata", "info", f"A security.txt document was directly available at {observation['url']} with fields {observation['value']['fields']}.",
                "Maintain the published security contact metadata and keep its expiration information current.", observation)

    return {
        "raw_findings": findings,
        "timeline": add_event(
            state, "passive-signals", "Collect Security Signals",
            f"Raw observations: {len(observations)}; generated signals: {len(findings)}",
            "passive_discovery.observations", f"Applied non-invasive rules to {len(observations)} collected observations and generated {len(findings)} evidence-backed signals.",
        ),
    }


def remediation_node(state: State):
    return {
        "timeline": add_event(
            state, "remediation", "Generate Remediation",
            f"Prepared evidence-aware impact and remediation guidance for {len(state.get('findings', []))} findings",
            "finding_impacts.potential_impact_for", "Applied deterministic guidance with safe fallback wording.",
        )
    }


def correlate_node(state: State):
    grouped = defaultdict(list)
    for item in state["raw_findings"]:
        grouped[(item["method"], item["endpoint"], item["category"])].append(item)

    findings = []
    for idx, ((method, endpoint, category), items) in enumerate(grouped.items(), start=1):
        severity = max((x["severity"] for x in items), key=lambda s: SEVERITY_ORDER[s])
        sources = sorted({
            source
            for item in items
            for source in (item.get("source_tools") or [item.get("source", "unknown")])
        })
        confidence = max(
            [float(item.get("confidence", 0)) for item in items] + [0.64 + min(0.24, 0.08 * len(items))]
        )
        if severity in {"high", "critical"}:
            confidence += 0.04

        evidence = []
        for item in items:
            item_evidence = item.get("evidence", [])
            if isinstance(item_evidence, str):
                item_evidence = [item_evidence]
            evidence.extend(str(value) for value in item_evidence if value)

        findings.append({
            "id": f"F-{idx:03d}",
            "source": sources[0] if len(sources) == 1 else "Correlated",
            "method": method,
            "endpoint": endpoint,
            "category": category,
            "severity": severity,
            "confidence": round(min(confidence, 0.94), 2),
            "evidence": list(dict.fromkeys(evidence)),
            "source_tools": sources,
            "potential_impact": items[0].get("potential_impact") or potential_impact_for(category, severity),
            "remediation": items[0].get("remediation") or REMEDIATION.get(category, "Review and validate this finding manually."),
            "status": "needs-review" if len(sources) == 1 else "supported",
        })

    findings.sort(key=lambda x: SEVERITY_ORDER[x["severity"]], reverse=True)

    return {
        "findings": findings,
        "timeline": add_event(
            state, "correlate", "Correlate Findings", f"Generated signals: {len(state['raw_findings'])}; final correlated findings: {len(findings)}",
            "graph.correlate_findings", f"Grouped {len(state['raw_findings'])} signals by method, endpoint, and defensive category into {len(findings)} findings.",
        ),
    }

def report_node(state: State):
    counts = defaultdict(int)
    for finding in state["findings"]:
        counts[finding["severity"]] += 1

    remediation_by_category = {}
    for finding in state["findings"]:
        category = finding["category"]
        item = remediation_by_category.setdefault(category, {
            "category": category,
            "severity": finding["severity"],
            "recommendation": finding["remediation"],
            "affected_endpoints": [],
            "finding_count": 0,
        })
        item["finding_count"] += 1
        endpoint = f"{finding['method']} {finding['endpoint']}"
        if endpoint not in item["affected_endpoints"]:
            item["affected_endpoints"].append(endpoint)
        if SEVERITY_ORDER[finding["severity"]] > SEVERITY_ORDER[item["severity"]]:
            item["severity"] = finding["severity"]

    remediation_report = sorted(
        remediation_by_category.values(),
        key=lambda item: SEVERITY_ORDER[item["severity"]],
        reverse=True,
    )
    timeline = add_event(
        state, "report", "Generate Report", "Created structured API security review report",
        "graph.build_report", f"Generated {len(remediation_report)} remediation workstreams.",
    )

    report = {
        "project": "APIShield Agent",
        "scan_mode": state.get("scan_mode", ScanMode.PASSIVE.value),
        "target": state.get("target"),
        "planning_mode": state["planning_mode"],
        "planning_fallback_reason": state.get("planning_fallback_reason"),
        "endpoint_count": len(state["endpoints"]),
        "plan": state["plan"],
        "timeline": timeline,
        "summary": {
            "total_findings": len(state["findings"]),
            "by_severity": dict(counts),
        },
        "findings": state["findings"],
        "observations": state.get("observations", []),
        "remediation_report": remediation_report,
        "disclaimer": "Passive findings are review signals and do not establish that harm occurred.",
    }

    return {"timeline": timeline, "report": report}

def build_graph():
    g = StateGraph(State)
    g.add_node("parse", parse_node)
    g.add_node("plan", plan_node)
    g.add_node("scan", scan_node)
    g.add_node("correlate", correlate_node)
    g.add_node("remediation", remediation_node)
    g.add_node("report", report_node)

    g.add_edge(START, "parse")
    g.add_edge("parse", "plan")
    g.add_edge("plan", "scan")
    g.add_edge("scan", "correlate")
    g.add_edge("correlate", "remediation")
    g.add_edge("remediation", "report")
    g.add_edge("report", END)

    return g.compile()


def build_passive_graph():
    g = StateGraph(State)
    g.add_node("plan", plan_node)
    g.add_node("passive-signals", passive_signal_node)
    g.add_node("correlate", correlate_node)
    g.add_node("remediation", remediation_node)
    g.add_node("report", report_node)
    g.add_edge(START, "plan")
    g.add_edge("plan", "passive-signals")
    g.add_edge("passive-signals", "correlate")
    g.add_edge("correlate", "remediation")
    g.add_edge("remediation", "report")
    g.add_edge("report", END)
    return g.compile()
