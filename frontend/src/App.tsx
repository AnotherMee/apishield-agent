import { FormEvent, useMemo, useState } from "react"
import { MAX_UPLOAD_BYTES, runActiveScan, runPassiveDiscovery, runSampleScan, runUploadScan } from "./api"
import type { ActiveScanJob, Observation, ScanReport, Severity } from "./types"

type Mode = "passive" | "active"
type PassiveInput = "url" | "openapi"

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

function ModeSelector({ mode, onChange }: { mode: Mode; onChange: (mode: Mode) => void }) {
  return (
    <section className="mode-section" aria-labelledby="mode-heading">
      <div className="section-intro">
        <span className="micro">ANALYSIS MODE</span>
        <h2 id="mode-heading">Choose the security boundary</h2>
        <p>Passive observation and authorized active testing are separate workflows with different trust requirements.</p>
      </div>
      <div className="mode-tabs" role="tablist" aria-label="Security analysis mode">
        <button
          type="button"
          role="tab"
          aria-selected={mode === "passive"}
          className={`mode-card passive-mode ${mode === "passive" ? "selected" : ""}`}
          onClick={() => onChange("passive")}
        >
          <span className="mode-label"><span className="mode-icon" aria-hidden="true">P</span> Passive Discovery</span>
          <strong>Low-risk observation</strong>
          <p>Ordinary HTTP requests and public API metadata. No exploit payloads, fuzzing, credential guessing, or active vulnerability testing.</p>
          <span className="mode-boundary">Ordinary requests · No active exploitation</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === "active"}
          className={`mode-card active-mode ${mode === "active" ? "selected" : ""}`}
          onClick={() => onChange("active")}
        >
          <span className="mode-label"><span className="mode-icon" aria-hidden="true">A</span> Authorized Active Scan</span>
          <strong>Authorization-gated DAST</strong>
          <p>Active security testing for targets you own or are explicitly authorized to test. OWASP ZAP is planned but not configured.</p>
          <span className="mode-boundary">Authorization required · Currently disabled</span>
        </button>
      </div>
    </section>
  )
}

function Observations({ observations }: { observations: Observation[] }) {
  if (!observations.length) return null
  return (
    <section className="panel observations-panel" aria-labelledby="observations-heading">
      <div className="panel-head">
        <div>
          <span className="micro">PASSIVE EVIDENCE</span>
          <h2 id="observations-heading">Observed Response Metadata</h2>
        </div>
        <span className="count-pill">{observations.length} observations</span>
      </div>
      <p className="observation-note">These are response observations and review signals, not confirmed exploitable vulnerabilities.</p>
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
          <span className="micro">ANALYSIS RESULT</span>
          <h2>{report.target || "OpenAPI specification"}</h2>
          <div className="report-tags">
            <span>{report.target ? "Passive Discovery" : "Passive OpenAPI Review"}</span>
            <span>{report.planning_mode} planning</span>
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
          <p className="observation-note">Findings identify conditions that need review; passive evidence is not proof of exploitability.</p>
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
                <div className="finding-section"><strong>Recommendation</strong><p>{finding.remediation}</p></div>
                <div className="source-row">{finding.source_tools.map((source) => <span key={source}>{source}</span>)}<span className="finding-status">{titleCase(finding.status)}</span></div>
              </article>
            )) : <div className="empty">No review findings were generated from the available evidence.</div>}
          </div>
          <div className="disclaimer">{report.disclaimer}</div>
        </div>
      </section>

      <section className="panel remediation-panel">
        <div className="panel-head">
          <div><span className="micro">FINAL REPORT</span><h2>Remediation Workstreams</h2></div>
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

function ActiveResult({ job }: { job: ActiveScanJob }) {
  return (
    <section className="panel active-result" role="status" aria-live="polite">
      <div className="status-symbol" aria-hidden="true">!</div>
      <div>
        <span className="micro">ACTIVE SCANNER STATUS</span>
        <h2>{titleCase(job.status)}</h2>
        <p>OWASP ZAP integration has not been enabled yet.</p>
        <p>{job.detail}</p>
        <div className="active-result-facts">
          <span><strong>Target</strong>{job.target}</span>
          <span><strong>Scanner</strong>OWASP ZAP</span>
          <span><strong>Findings</strong>{job.findings.length}</span>
        </div>
        <div className="safety-confirmation">No active security testing was performed. No findings were fabricated or simulated.</div>
      </div>
    </section>
  )
}

export default function App() {
  const [mode, setMode] = useState<Mode>("passive")
  const [passiveInput, setPassiveInput] = useState<PassiveInput>("url")
  const [target, setTarget] = useState("")
  const [activeTarget, setActiveTarget] = useState("")
  const [authorized, setAuthorized] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [useAI, setUseAI] = useState(true)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [activeJob, setActiveJob] = useState<ActiveScanJob | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  function switchMode(next: Mode) {
    setMode(next)
    setError("")
    setReport(null)
    setActiveJob(null)
  }

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

  function submitPassive(event: FormEvent) {
    event.preventDefault()
    if (!isValidHttpUrl(target)) {
      setError("Enter a valid public URL beginning with http:// or https://.")
      return
    }
    void execute(async () => {
      setReport(await runPassiveDiscovery(target, useAI))
      setActiveJob(null)
    })
  }

  function submitActive(event: FormEvent) {
    event.preventDefault()
    if (!authorized) {
      setError("Authorization acknowledgement is required before requesting an active scan.")
      return
    }
    if (!isValidHttpUrl(activeTarget)) {
      setError("Enter a valid target URL beginning with http:// or https://.")
      return
    }
    void execute(async () => {
      setActiveJob(await runActiveScan(activeTarget, useAI))
      setReport(null)
    })
  }

  function sampleScan() {
    void execute(async () => {
      setReport(await runSampleScan(useAI))
      setActiveJob(null)
    })
  }

  function uploadScan() {
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      setError("The selected OpenAPI file exceeds the 2 MB upload limit.")
      return
    }
    void execute(async () => {
      setReport(await runUploadScan(file, useAI))
      setActiveJob(null)
    })
  }

  return (
    <div className="page" aria-busy={loading}>
      <nav className="nav">
        <div className="brand"><div className="brand-mark">A</div><div><strong>APIShield</strong><span>Agent</span></div></div>
        <div className="nav-pill">Defensive Security Analysis</div>
      </nav>

      <header className="hero compact-hero">
        <div className="hero-copy">
          <div className="kicker">AGENTIC API SECURITY REVIEW</div>
          <h1>One workspace. Two explicit security boundaries.</h1>
          <p>Observe public API behavior with low-risk requests, or prepare an authorization-gated active scan workflow for future OWASP ZAP integration.</p>
        </div>
        <div className="trust-summary panel">
          <span className="micro">CURRENT CAPABILITY</span>
          <div><strong>Passive Discovery</strong><span>Available</span></div>
          <div><strong>Authorized Active Scan</strong><span>Not configured</span></div>
        </div>
      </header>

      <main>
        <ModeSelector mode={mode} onChange={switchMode} />

        {mode === "passive" ? (
          <section className="panel configuration-panel" role="tabpanel" aria-label="Passive Discovery configuration">
            <div className="panel-head">
              <div><span className="micro">PASSIVE CONFIGURATION</span><h2>Choose a passive input</h2></div>
              <span className="risk-badge low-risk">Low-risk workflow</span>
            </div>
            <fieldset className="input-switcher">
              <legend className="sr-only">Passive analysis input</legend>
              <label><input type="radio" name="passive-input" value="url" checked={passiveInput === "url"} onChange={() => { setPassiveInput("url"); setError("") }} /><span>Analyze URL</span></label>
              <label><input type="radio" name="passive-input" value="openapi" checked={passiveInput === "openapi"} onChange={() => { setPassiveInput("openapi"); setError("") }} /><span>Analyze OpenAPI specification</span></label>
            </fieldset>

            {passiveInput === "url" ? (
              <form className="target-form" onSubmit={submitPassive}>
                <label htmlFor="passive-target">Public target URL</label>
                <span>APIShield makes bounded ordinary HTTP requests. Internal, private, loopback, link-local, credential-bearing, and malformed targets are rejected.</span>
                <div className="url-row">
                  <input id="passive-target" type="url" inputMode="url" placeholder="https://api.example.com" value={target} onChange={(event) => setTarget(event.target.value)} required />
                  <button type="submit" disabled={loading}>{loading ? "Discovering…" : "Run Passive Discovery"}</button>
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
                  <button type="button" onClick={uploadScan} disabled={!file || loading}>{loading ? "Analyzing…" : "Analyze Upload"}</button>
                  <button type="button" className="ghost" onClick={sampleScan} disabled={loading}>Run Sample Specification</button>
                </div>
              </div>
            )}

            <label className="ai-toggle">
              <input type="checkbox" checked={useAI} onChange={(event) => setUseAI(event.target.checked)} />
              <div><strong>Use AI-assisted planning</strong><span>Falls back to deterministic planning when the backend has no OpenAI key.</span></div>
            </label>
            {error && <div className="error" role="alert">{error}</div>}
          </section>
        ) : (
          <section className="panel configuration-panel active-configuration" role="tabpanel" aria-label="Authorized Active Scan configuration">
            <div className="panel-head">
              <div><span className="micro active-micro">AUTHORIZED ACTIVE CONFIGURATION</span><h2>Prepare an authorization-gated scan</h2></div>
              <span className="risk-badge authorization-required">Authorization required</span>
            </div>
            <div className="authorization-notice" role="note">
              <strong>Active security testing trust boundary</strong>
              <p>This workflow is intended only for systems you own or have explicit permission to test. OWASP ZAP is planned, but active scanning is not currently enabled.</p>
            </div>
            <form className="target-form" onSubmit={submitActive}>
              <label htmlFor="active-target">Authorized target URL</label>
              <input id="active-target" type="url" inputMode="url" placeholder="https://authorized-api.example.com" value={activeTarget} onChange={(event) => setActiveTarget(event.target.value)} required />
              <div className="scanner-status" aria-label="Scanner configuration">
                <span><small>Scanner</small><strong>OWASP ZAP</strong></span>
                <span><small>Scanner status</small><strong>Not configured</strong></span>
                <span><small>Current behavior</small><strong>No target contact</strong></span>
              </div>
              <label className="authorization-check" htmlFor="authorization-confirmation">
                <input id="authorization-confirmation" type="checkbox" checked={authorized} onChange={(event) => { setAuthorized(event.target.checked); setError("") }} />
                <span>I confirm that I own this target or have explicit authorization to perform security testing against it.</span>
              </label>
              <button type="submit" disabled={!authorized || loading} aria-describedby={!authorized ? "active-disabled-reason" : undefined}>
                {loading ? "Checking scanner…" : "Run Active Scan"}
              </button>
              {!authorized && <p id="active-disabled-reason" className="disabled-reason">Acknowledge authorization to enable this request. The scanner remains unavailable until OWASP ZAP is configured.</p>}
            </form>
            {error && <div className="error" role="alert">{error}</div>}
          </section>
        )}

        {loading && <div className="loading-banner" role="status" aria-live="polite">APIShield is processing the request…</div>}
        {report && <ReportResults report={report} />}
        {activeJob && <ActiveResult job={activeJob} />}
      </main>

      <footer><span>APIShield Agent</span><span>LangGraph · FastAPI · React · OpenAI-ready</span></footer>
    </div>
  )
}
