from collections import defaultdict
from langgraph.graph import StateGraph, START, END
from typing import TypedDict

from app.tools.openapi_parser import load_spec, inventory
from app.tools.scanners import collect_defensive_signals
from app.agents.planner import create_plan
from app.models import ScanMode
from app.services.active_scan import active_scan_capability

class State(TypedDict, total=False):
    spec_path: str
    use_ai: bool
    scan_mode: str
    target: str | None
    endpoints: list[dict]
    observations: list[dict]
    plan: list[dict]
    planning_mode: str
    raw_findings: list[dict]
    findings: list[dict]
    timeline: list[dict]
    report: dict
    active_job: dict

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
    plan, mode = create_plan(state["endpoints"], state["use_ai"])
    return {
        "plan": plan,
        "planning_mode": mode,
        "timeline": add_event(
            state, "plan", "Plan Review", f"Generated {len(plan)} prioritized steps using {mode} planning",
            "planner.create_plan", f"Produced a schema-validated {mode.lower()} defensive review plan.",
        ),
    }

def scan_node(state: State):
    findings = collect_defensive_signals(state["endpoints"])
    return {
        "raw_findings": findings,
        "timeline": add_event(
            state, "scan", "Collect Signals", f"Collected {len(findings)} defensive review signals",
            "scanners.collect_defensive_signals", f"Applied passive metadata rules to {len(state['endpoints'])} endpoints.",
        ),
    }


def passive_signal_node(state: State):
    observations = state.get("observations", [])
    by_category = {item["category"]: item for item in observations}
    target = state.get("target") or "unknown"
    findings = []

    def add(category: str, severity: str, evidence: str, remediation: str):
        findings.append({
            "source": "passive-http",
            "method": "GET",
            "endpoint": target,
            "category": category,
            "severity": severity,
            "evidence": evidence,
            "remediation": remediation,
        })

    https = by_category.get("https-usage")
    if https and not https["value"]:
        add("insecure-transport", "medium", "The final response was served over HTTP rather than HTTPS.",
            "Serve the API over HTTPS and redirect HTTP traffic to HTTPS.")

    security = by_category.get("security-headers")
    if security:
        present = security["value"]
        checked = security.get("metadata", {}).get("checked", [])
        missing = [name for name in checked if name not in present]
        if missing:
            add("missing-security-headers", "low", f"Missing response security headers: {', '.join(missing)}.",
                "Return security headers appropriate to the API response and deployment context.")

    cors = by_category.get("cors-headers")
    if cors and cors["value"].get("access-control-allow-origin") == "*":
        credentials = cors["value"].get("access-control-allow-credentials", "").lower() == "true"
        add("permissive-cors", "high" if credentials else "medium",
            "The response declares Access-Control-Allow-Origin: *." + (" Credentials are also allowed." if credentials else ""),
            "Restrict CORS to explicitly trusted origins and avoid credentialed wildcard policies.")

    metadata = by_category.get("server-metadata")
    if metadata and metadata["value"]:
        add("server-metadata-exposure", "info", f"The response exposed server metadata: {metadata['value']}.",
            "Minimize unnecessary product and intermediary version disclosure in response headers.")

    for observation in observations:
        if observation["category"] == "public-openapi-document":
            add("public-api-metadata", "info", f"A public API description was available at {observation['url']}.",
                "Confirm that public API metadata is intentional and does not disclose internal-only operations.")

    return {
        "raw_findings": findings,
        "timeline": add_event(
            state, "passive-signals", "Analyze Passive Observations",
            f"Converted {len(observations)} observations into {len(findings)} review signals",
            "passive_discovery.observations", "Applied non-invasive rules to ordinary HTTP response metadata.",
        ),
    }


def active_placeholder_node(state: State):
    capability = active_scan_capability()
    job = {
        "id": None,
        "scan_mode": ScanMode.AUTHORIZED_ACTIVE.value,
        "target": state.get("target") or "",
        "provider": capability.provider,
        "status": "not-configured",
        "capability": capability.model_dump(),
        "findings": [],
        "detail": capability.detail,
    }
    return {
        "active_job": job,
        "raw_findings": [],
        "timeline": add_event(
            state, "active-placeholder", "Check Active Scanner Capability",
            "No active scan was started and no target traffic was sent",
            "active_scan.capability", capability.detail,
        ),
    }

def correlate_node(state: State):
    grouped = defaultdict(list)
    for item in state["raw_findings"]:
        grouped[(item["method"], item["endpoint"], item["category"])].append(item)

    findings = []
    for idx, ((method, endpoint, category), items) in enumerate(grouped.items(), start=1):
        severity = max((x["severity"] for x in items), key=lambda s: SEVERITY_ORDER[s])
        sources = sorted({x["source"] for x in items})
        confidence = 0.64 + min(0.24, 0.08 * len(items))
        if severity in {"high", "critical"}:
            confidence += 0.04

        findings.append({
            "id": f"F-{idx:03d}",
            "method": method,
            "endpoint": endpoint,
            "category": category,
            "severity": severity,
            "confidence": round(min(confidence, 0.94), 2),
            "evidence": [x["evidence"] for x in items],
            "source_tools": sources,
            "remediation": items[0].get("remediation") or REMEDIATION.get(category, "Review and validate this finding manually."),
            "status": "needs-review" if len(sources) == 1 else "supported",
        })

    findings.sort(key=lambda x: SEVERITY_ORDER[x["severity"]], reverse=True)

    return {
        "findings": findings,
        "timeline": add_event(
            state, "correlate", "Correlate Findings", f"Consolidated signals into {len(findings)} findings",
            "graph.correlate_findings", f"Grouped signals by method, endpoint, and defensive category.",
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
        "disclaimer": "Only assess APIs you own or are explicitly authorized to test.",
    }

    return {"timeline": timeline, "report": report}

def build_graph():
    g = StateGraph(State)
    g.add_node("parse", parse_node)
    g.add_node("plan", plan_node)
    g.add_node("scan", scan_node)
    g.add_node("correlate", correlate_node)
    g.add_node("report", report_node)

    g.add_edge(START, "parse")
    g.add_edge("parse", "plan")
    g.add_edge("plan", "scan")
    g.add_edge("scan", "correlate")
    g.add_edge("correlate", "report")
    g.add_edge("report", END)

    return g.compile()


def build_passive_graph():
    g = StateGraph(State)
    g.add_node("plan", plan_node)
    g.add_node("passive-signals", passive_signal_node)
    g.add_node("correlate", correlate_node)
    g.add_node("report", report_node)
    g.add_edge(START, "plan")
    g.add_edge("plan", "passive-signals")
    g.add_edge("passive-signals", "correlate")
    g.add_edge("correlate", "report")
    g.add_edge("report", END)
    return g.compile()


def build_active_graph():
    g = StateGraph(State)
    g.add_node("plan", plan_node)
    g.add_node("active-placeholder", active_placeholder_node)
    g.add_node("correlate", correlate_node)
    g.add_node("report", report_node)
    g.add_edge(START, "plan")
    g.add_edge("plan", "active-placeholder")
    g.add_edge("active-placeholder", "correlate")
    g.add_edge("correlate", "report")
    g.add_edge("report", END)
    return g.compile()
