import { useMemo } from "react"
import type { ScanReport, Severity } from "../types"

export function MetricsPanel({ report }: { report: ScanReport }) {
  const highest = useMemo(() => {
    const order: Severity[] = ["critical", "high", "medium", "low", "info"]
    return order.find((severity) => (report.summary.by_severity[severity] || 0) > 0)?.toUpperCase() || "NONE"
  }, [report])

  return (
    <section className="card metrics-panel" aria-labelledby="overview-heading">
      <div className="report-header">
        <div className="section-heading"><span>OVERVIEW</span><h2 id="overview-heading">{report.target || "OpenAPI specification"}</h2></div>
        <div className="report-tags">
          <span>{report.target ? "Passive URL Review" : "Passive OpenAPI Review"}</span>
          {report.planning_fallback_reason && <span className="fallback-tag">Fallback: {report.planning_fallback_reason}</span>}
        </div>
      </div>
      <div className="metrics">
        <div><span>Endpoints</span><strong>{report.endpoint_count}</strong></div>
        <div><span>Findings</span><strong>{report.summary.total_findings}</strong></div>
        <div><span>Highest Risk</span><strong className={`risk-value risk-${highest.toLowerCase()}`}>{highest}</strong></div>
        <div><span>Planning Mode</span><strong>{report.planning_mode}</strong></div>
      </div>
    </section>
  )
}
