import { FormEvent, useMemo, useState } from "react"
import { MAX_UPLOAD_BYTES, runPassiveDiscovery, runSampleScan, runUploadScan } from "./api"
import type { Observation, ScanReport, Severity } from "./types"

type ReviewInput = "url" | "openapi"

function severityClass(severity: string) {
  return `severity severity-${severity}`
}

function titleCase(value: string) {
  return value.replaceAll("-", " ").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function isValidHttpUrl(value: string) {
  try {
    const url = new URL(value)
    return url.protocol === "http:" || url.protocol === "https:"
  } catch {
    return false
  }
}

function observationValue(observation: Observation) {
  const value = observation.value
  if (observation.category === "https-usage") return value ? "HTTPS enabled" : "HTTP only"
  if (observation.category === "response-size" && typeof value === "number") return `${value.toLocaleString()} bytes`
  if (observation.category === "redirects" && Array.isArray(value)) {
    return value.length ? value.map((item) => JSON.stringify(item)).join("\n") : "No redirects"
  }
  if (value && typeof value === "object") {
    return Object.keys(value as object).length ? JSON.stringify(value, null, 2) : "None observed"
  }
  if (value === "") return "Not reported"
  return String(value)
}

function Observations({ observations }: { observations: Observation[] }) {
  if (!observations.length) return null
  return (
    <section className="panel observations-panel" aria-labelledby="observations-heading">
      <div className="panel-head">
        <div><span className="micro">PASSIVE EVIDENCE</span><h2 id="observations-heading">Observed Response Metadata</h2></div>
        <span className="count-pill">{observations.length} observations</span>
      </div>
      <p className="observation-note">These are response observations and review signals, not confirmed security incidents.</p>
      <div className="observation-grid">
        {observations.map((observation, index) => (
          <article className={`observation-card observation-${observation.category}`} key={`${observation.category}-${observation.url}-${index}`}>
            <span>{titleCase(observation.category)}</span>
            <pre>{observationValue(observation)}</pre>
            <small>{observation.url}</small>
          </article>
        ))}
      </div>
    </section>
  )
}

function ReportResults({ report }: { report: ScanReport }) {
  const highest = useMemo(() => {
    const order: Severity[] = ["critical", "high", "medium", "low", "info"]
    return order.find((severity) => (report.summary.by_severity[severity] || 0) > 0)?.toUpperCase() || "NONE"
  }, [report])

  return (
    <div className="report-stack">
      <section className="panel report-overview" aria-label="Analysis overview">
        <div className="report-identity">
          <span className="micro">SECURITY REVIEW RESULT</span>
          <h2>{report.target || "OpenAPI specification"}</h2>
          <div className="report-tags">
            <span>{report.target ? "Passive URL Review" : "Passive OpenAPI Review"}</span>
            <span>{report.planning_mode} planning</span>
            {report.planning_fallback_reason && <span className="fallback-tag">Fallback: {report.planning_fallback_reason}</span>}
          </div>
        </div>
        <div className="metrics">
          <div className="metric"><span>Endpoints</span><strong>{report.endpoint_count}</strong></div>
          <div className="metric"><span>Findings</span><strong>{report.summary.total_findings}</strong></div>
          <div className="metric"><span>Highest Risk</span><strong>{highest}</strong></div>
          <div className="metric"><span>Workflow</span><strong>{report.timeline.length}</strong></div>
        </div>
      </section>

      <Observations observations={report.observations || []} />

      <section className="results-grid">
        <div className="panel trace-panel">
          <div className="panel-head">
            <div><span className="micro">WORKFLOW</span><h2>LangGraph Execution</h2></div>
            <span className="count-pill">{report.timeline.length} nodes</span>
          </div>
          <div className="timeline">
            {report.timeline.map((item, index) => (
              <div className="timeline-row" key={`${item.node}-${index}`}>
                <div className="timeline-node">{index + 1}</div>
                <div className="timeline-content">
                  <div className="node-heading">
                    <div><code className="node-id">{item.node}</code><strong>{item.step}</strong></div>
                    <span className="completed-pill">{item.status}</span>
                  </div>
                  <span className="node-detail">{item.detail}</span>
                  <div className="tool-list">
                    {item.tool_invocations.map((tool) => (
                      <div className="tool-invocation" key={tool.name}>
                        <div className="tool-icon">T</div>
                        <div><code>{tool.name}</code><p>{tool.summary}</p></div>
                        <span>{tool.status}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="plan-box">
            <h3>Agent Plan</h3>
            <ol>
              {report.plan.map((step, index) => (
                <li key={`${step.title}-${index}`}>
                  <div className="plan-title"><span className={severityClass(step.priority)}>{step.priority}</span><strong>{step.title}</strong></div>
                  <p>{step.rationale}</p>
                  {!!step.endpoints.length && <div className="plan-endpoints">{step.endpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}</div>}
                </li>
              ))}
            </ol>
          </div>
        </div>

        <div className="panel findings-panel">
          <div className="panel-head">
            <div><span className="micro">NORMALIZED OUTPUT</span><h2>Security Review Findings</h2></div>
            <span className="count-pill">{report.findings.length} findings</span>
          </div>
          <p className="observation-note">Findings identify conditions that need review; passive evidence does not establish that harm occurred.</p>
          <div className="findings">
            {report.findings.length ? report.findings.map((finding) => (
              <article className="finding" key={finding.id}>
                <div className="finding-top">
                  <div><div className="endpoint-row"><span className="method">{finding.method}</span><code>{finding.endpoint}</code></div><h3>{titleCase(finding.category)}</h3></div>
                  <span className={severityClass(finding.severity)}>{finding.severity}</span>
                </div>
                <div className="confidence-row"><span>Confidence</span><strong>{Math.round(finding.confidence * 100)}%</strong></div>
                <div className="confidence-track"><div style={{ width: `${Math.round(finding.confidence * 100)}%` }} /></div>
                <div className="finding-section"><strong>Evidence</strong><ul>{finding.evidence.map((evidence, index) => <li key={index}>{evidence}</li>)}</ul></div>
                <div className="finding-section impact-section"><strong>Potential Impact</strong><p>{finding.potential_impact}</p></div>
                <div className="finding-section"><strong>Recommendation</strong><p>{finding.remediation}</p></div>
                <div className="source-row">{finding.source_tools.map((source) => <span key={source}>Source: {source}</span>)}<span className="finding-status">{titleCase(finding.status)}</span></div>
              </article>
            )) : <div className="empty">No review findings were generated from the available evidence.</div>}
          </div>
          <div className="disclaimer">{report.disclaimer}</div>
        </div>
      </section>

      <section className="panel remediation-panel">
        <div className="panel-head">
          <div><span className="micro">AI-ASSISTED REMEDIATION</span><h2>Remediation Workstreams</h2></div>
          <span className="count-pill">{report.remediation_report.length} priorities</span>
        </div>
        {report.remediation_report.length ? (
          <div className="remediation-grid">
            {report.remediation_report.map((item, index) => (
              <article className="remediation-card" key={item.category}>
                <div className="remediation-rank">{String(index + 1).padStart(2, "0")}</div>
                <div className="remediation-body">
                  <div className="remediation-heading"><h3>{titleCase(item.category)}</h3><span className={severityClass(item.severity)}>{item.severity}</span></div>
                  <p>{item.recommendation}</p>
                  <div className="affected-list"><span>{item.finding_count} {item.finding_count === 1 ? "finding" : "findings"}</span>{item.affected_endpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}</div>
                </div>
              </article>
            ))}
          </div>
        ) : <div className="empty">No remediation workstreams were generated.</div>}
      </section>
    </div>
  )
}

export default function App() {
  const [reviewInput, setReviewInput] = useState<ReviewInput>("url")
  const [target, setTarget] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [useAI, setUseAI] = useState(true)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  async function execute(task: () => Promise<void>) {
    setLoading(true)
    setError("")
    try {
      await task()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The request could not be completed.")
    } finally {
      setLoading(false)
    }
  }

  function submitUrl(event: FormEvent) {
    event.preventDefault()
    if (!isValidHttpUrl(target)) {
      setError("Enter a valid public URL beginning with http:// or https://.")
      return
    }
    void execute(async () => setReport(await runPassiveDiscovery(target, useAI)))
  }

  function sampleScan() {
    void execute(async () => setReport(await runSampleScan(useAI)))
  }

  function uploadScan() {
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      setError("The selected OpenAPI file exceeds the 2 MB upload limit.")
      return
    }
    void execute(async () => setReport(await runUploadScan(file, useAI)))
  }

  return (
    <div className="page" aria-busy={loading}>
      <nav className="nav">
        <div className="brand"><div className="brand-mark">A</div><div><strong>APIShield</strong><span>Agent</span></div></div>
        <div className="nav-pill">Passive Defensive Analysis</div>
      </nav>

      <header className="hero compact-hero">
        <div className="hero-copy">
          <div className="kicker">AGENTIC API SECURITY REVIEW</div>
          <h1>APIShield — Agentic API Security Review</h1>
          <p>Discover API security risks, correlate evidence through LangGraph, and generate AI-assisted remediation guidance.</p>
        </div>
        <div className="trust-summary panel">
          <span className="micro">TRUST BOUNDARY</span>
          <strong>Passive defensive analysis</strong>
          <p>Uses bounded ordinary requests and supplied API metadata.</p>
        </div>
      </header>

      <main>
        <section className="panel configuration-panel" aria-labelledby="review-heading">
          <div className="panel-head">
            <div><span className="micro">START A SECURITY REVIEW</span><h2 id="review-heading">Choose an input</h2></div>
            <span className="risk-badge low-risk">Passive review</span>
          </div>
          <fieldset className="input-switcher">
            <legend className="sr-only">Security review input</legend>
            <label><input type="radio" name="review-input" value="url" checked={reviewInput === "url"} onChange={() => { setReviewInput("url"); setError("") }} /><span>Analyze URL</span></label>
            <label><input type="radio" name="review-input" value="openapi" checked={reviewInput === "openapi"} onChange={() => { setReviewInput("openapi"); setError("") }} /><span>Analyze OpenAPI</span></label>
          </fieldset>

          {reviewInput === "url" ? (
            <form className="target-form" onSubmit={submitUrl}>
              <label htmlFor="review-target">Target URL</label>
              <span>APIShield makes bounded ordinary HTTP requests and blocks internal, private, loopback, link-local, credential-bearing, and malformed targets.</span>
              <div className="url-row">
                <input id="review-target" type="url" inputMode="url" placeholder="https://api.example.com" value={target} onChange={(event) => setTarget(event.target.value)} required />
                <button type="submit" disabled={loading}>{loading ? "Reviewing…" : "Start Security Review"}</button>
              </div>
            </form>
          ) : (
            <div className="openapi-workspace">
              <label className="upload">
                <input type="file" accept=".yaml,.yml,.json" onChange={(event) => { setFile(event.target.files?.[0] || null); setError("") }} />
                <div className="upload-icon" aria-hidden="true">↑</div>
                <strong>{file ? file.name : "Upload OpenAPI specification"}</strong>
                <span>YAML or JSON · 2 MB maximum · Static metadata review</span>
              </label>
              <div className="scan-actions">
                <button type="button" onClick={uploadScan} disabled={!file || loading}>{loading ? "Reviewing…" : "Analyze Upload"}</button>
                <button type="button" className="ghost" onClick={sampleScan} disabled={loading}>Run Sample Specification</button>
              </div>
            </div>
          )}

          <label className="ai-toggle">
            <input type="checkbox" checked={useAI} onChange={(event) => setUseAI(event.target.checked)} />
            <div><strong>Use AI-assisted planning</strong><span>Uses deterministic planning when OpenAI is unavailable and reports the fallback reason.</span></div>
          </label>
          <p className="workflow-summary">URL or OpenAPI → Security Review → Findings → Remediation</p>
          {error && <div className="error" role="alert">{error}</div>}
        </section>

        {loading && <div className="loading-banner" role="status" aria-live="polite">APIShield is processing the security review…</div>}
        {report && <ReportResults report={report} />}
      </main>

      <footer><span>APIShield Agent</span><span>LangGraph · FastAPI · React · OpenAI-ready</span></footer>
    </div>
  )
}
