import type { RemediationItem } from "../types"
import { severityClass, titleCase } from "../utils"

export function RemediationPanel({ items }: { items: RemediationItem[] }) {
  return (
    <section className="card remediation-panel" aria-labelledby="remediation-heading">
      <div className="panel-heading-row">
        <div className="section-heading"><span>GUIDANCE</span><h2 id="remediation-heading">AI-Assisted Remediation</h2></div>
        <span className="count-badge">{items.length} priorities</span>
      </div>
      {items.length ? <div className="remediation-grid">
        {items.map((item, index) => (
          <article className="remediation-item" key={item.category}>
            <div className="remediation-top"><span className="priority">P{index + 1}</span><span className={severityClass(item.severity)}>{item.severity}</span></div>
            <h3>{titleCase(item.category)}</h3>
            <div className="guidance-field"><span>Recommended Action</span><p>{item.recommendation}</p></div>
            <div className="guidance-field"><span>Affected Scope</span><div>{item.affected_endpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}</div></div>
          </article>
        ))}
      </div> : <div className="empty">No remediation workstreams were generated.</div>}
      <button type="button" className="report-action" onClick={() => document.getElementById("remediation-heading")?.scrollIntoView({ behavior: "smooth" })}>View Remediation Report →</button>
    </section>
  )
}
