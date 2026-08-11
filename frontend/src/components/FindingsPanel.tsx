import type { Finding } from "../types"
import { severityClass, titleCase } from "../utils"

export function FindingsPanel({ findings, disclaimer }: { findings: Finding[]; disclaimer: string }) {
  return (
    <section className="card findings-panel" aria-labelledby="findings-heading">
      <div className="panel-heading-row">
        <div className="section-heading"><span>NORMALIZED OUTPUT</span><h2 id="findings-heading">Security Review Findings</h2></div>
        <span className="count-badge">{findings.length}</span>
      </div>
      <p className="panel-note">Passive evidence identifies conditions for review and does not establish that harm occurred.</p>
      <div className="findings-list">
        {findings.length ? findings.map((finding) => (
          <article className="finding" key={finding.id}>
            <div className="finding-header">
              <span className={severityClass(finding.severity)}>{finding.severity}</span>
              <div className="finding-title"><h3>{titleCase(finding.category)}</h3><code>{finding.method} {finding.endpoint}</code></div>
              <div className="finding-meta"><span>Confidence <strong>{Math.round(finding.confidence * 100)}%</strong></span><span>Source <strong>{finding.source_tools.join(", ")}</strong></span></div>
            </div>
            <div className="finding-sections">
              <section><span>Evidence</span><ul>{finding.evidence.map((evidence, index) => <li key={index}>{evidence}</li>)}</ul></section>
              <section className="impact"><span>Potential Impact</span><p>{finding.potential_impact}</p></section>
              <section><span>Recommendation</span><p>{finding.remediation}</p></section>
            </div>
          </article>
        )) : <div className="empty">No review findings were generated from the available evidence.</div>}
      </div>
      <p className="disclaimer">{disclaimer}</p>
    </section>
  )
}
