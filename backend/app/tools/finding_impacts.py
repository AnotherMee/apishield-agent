POTENTIAL_IMPACTS = {
    "missing-authentication": (
        "If the route is reachable as described, unauthenticated users may be able to access functionality "
        "that was intended for trusted users or administrators."
    ),
    "object-level-authorization-review": (
        "If object-level authorization is incomplete, identifiers could be used to access or modify records "
        "outside the caller's permitted scope."
    ),
    "input-validation-review": (
        "Insufficient server-side validation may allow unexpected data to reach application logic and can "
        "increase the risk of injection, data-integrity, or availability issues."
    ),
    "data-access-review": (
        "If untrusted input reaches data-access operations without safe handling, it could increase the risk "
        "of unauthorized data access or modification."
    ),
    "insecure-transport": (
        "Traffic sent without HTTPS may be exposed to interception or modification on an untrusted network."
    ),
    "missing-security-headers": (
        "Missing defensive headers may weaken browser-side protections and, if combined with another "
        "vulnerability, could increase the impact of content injection or framing attacks."
    ),
    "permissive-cors": (
        "An overly broad CORS policy may allow untrusted origins to read API responses in a user's browser, "
        "particularly if combined with credentials or weak authorization controls."
    ),
    "server-metadata-exposure": (
        "Exposed product or intermediary metadata can assist reconnaissance and may help an attacker focus "
        "follow-up testing on known component weaknesses."
    ),
    "public-api-metadata": (
        "Public API descriptions may disclose operations, parameters, or internal conventions that can "
        "increase the efficiency of reconnaissance if publication was not intended."
    ),
    "injection": (
        "If the reported condition is exploitable, crafted input could affect interpreter behavior and may "
        "lead to unauthorized data access, modification, or service disruption."
    ),
    "cross-site-scripting": (
        "If exploitable in a browser context, untrusted script execution could expose user data or perform "
        "actions with the affected user's privileges."
    ),
    "authentication": (
        "Weak authentication controls may allow an unauthorized party to assume another user's identity or "
        "reach protected functionality."
    ),
    "authorization": (
        "Weak authorization controls could allow authenticated users to access data or actions outside their "
        "assigned permissions."
    ),
    "sensitive-data-exposure": (
        "The reported condition may expose confidential information and could increase privacy, compliance, "
        "or account-compromise risk."
    ),
    "server-side-request-forgery": (
        "If exploitable, the server could be induced to contact unintended destinations, potentially exposing "
        "internal services or cloud metadata."
    ),
    "path-traversal": (
        "If exploitable, crafted paths could allow access to files outside the intended directory boundary."
    ),
    "security-header": (
        "Missing or weak response headers may reduce browser-side defenses and can increase the impact of "
        "another client-side vulnerability."
    ),
    "cryptography": (
        "Weak cryptographic handling may reduce confidentiality or integrity protections for affected data."
    ),
}


def potential_impact_for(category: str, severity: str = "medium") -> str:
    normalized = category.lower().replace("_", "-")
    if normalized in POTENTIAL_IMPACTS:
        return POTENTIAL_IMPACTS[normalized]
    for known, impact in POTENTIAL_IMPACTS.items():
        if known in normalized or normalized in known:
            return impact
    if severity in {"critical", "high"}:
        return (
            "If the reported condition is confirmed and exploitable, it could materially affect the "
            "confidentiality, integrity, or availability of the affected API."
        )
    return (
        "The condition may reduce defensive assurance and, if combined with another vulnerability, could "
        "increase risk to the affected API or its users."
    )
