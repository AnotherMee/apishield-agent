export type Severity = "info" | "low" | "medium" | "high" | "critical"
export type ScanMode = "passive" | "authorized_active"

export type Finding = {
  id: string
  method: string
  endpoint: string
  category: string
  severity: Severity
  confidence: number
  evidence: string[]
  source_tools: string[]
  remediation: string
  status: string
  correlation?: Record<string, unknown> | null
}

export type ToolInvocation = {
  name: string
  status: string
  summary: string
}

export type TimelineItem = {
  node: string
  step: string
  detail: string
  status: string
  tool_invocations: ToolInvocation[]
}

export type ReviewStep = {
  priority: Exclude<Severity, "info">
  title: string
  rationale: string
  endpoints: string[]
}

export type RemediationItem = {
  category: string
  severity: Severity
  recommendation: string
  affected_endpoints: string[]
  finding_count: number
}

export type Observation = {
  category: string
  source: string
  url: string
  value: unknown
  metadata: Record<string, unknown>
}

export type ScanReport = {
  project: string
  scan_mode?: ScanMode
  target?: string | null
  planning_mode: string
  endpoint_count: number
  plan: ReviewStep[]
  timeline: TimelineItem[]
  observations?: Observation[]
  summary: {
    total_findings: number
    by_severity: Record<string, number>
  }
  findings: Finding[]
  remediation_report: RemediationItem[]
  disclaimer: string
}

export type ScannerCapability = {
  provider: string
  configured: boolean
  available: boolean
  status: "ready" | "not-configured" | "disabled"
  detail: string
}

export type ActiveScanJob = {
  id: string | null
  scan_mode: "authorized_active"
  target: string
  provider: string
  status: "not-configured" | "queued" | "running" | "completed" | "failed" | "cancelled"
  capability: ScannerCapability
  findings: Finding[]
  detail: string
}
