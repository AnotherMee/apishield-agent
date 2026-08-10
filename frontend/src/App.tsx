import { useMemo, useState } from "react"

type Finding = {
  id: string
  method: string
  endpoint: string
  category: string
  severity: "info" | "low" | "medium" | "high" | "critical"
  confidence: number
  evidence: string[]
  source_tools: string[]
  remediation: string
  status: string
}

type TimelineItem = {
  node: string
  step: string
  detail: string
  status: string
  tool_invocations: ToolInvocation[]
}

type ToolInvocation = {
  name: string
  status: string
  summary: string
}

type ReviewStep = {
  priority: "critical" | "high" | "medium" | "low"
  title: string
  rationale: string
  endpoints: string[]
}

type RemediationItem = {
  category: string
  severity: Finding["severity"]
  recommendation: string
  affected_endpoints: string[]
  finding_count: number
}

type Report = {
  project: string
  planning_mode: string
  endpoint_count: number
  plan: ReviewStep[]
  timeline: TimelineItem[]
  summary: {
    total_findings: number
    by_severity: Record<string, number>
  }
  findings: Finding[]
  remediation_report: RemediationItem[]
  disclaimer: string
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024

function severityClass(severity: string) {
  return `severity severity-${severity}`
}

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [useAI, setUseAI] = useState(true)
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const highest = useMemo(() => {
    if (!report) return "—"
    const order = ["critical", "high", "medium", "low", "info"]
    return order.find((x) => (report.summary.by_severity[x] || 0) > 0)?.toUpperCase() || "NONE"
  }, [report])

  async function responseError(res: Response, fallback: string) {
    const data = await res.json().catch(() => null) as { detail?: string } | null
    return data?.detail || `${fallback} (${res.status})`
  }

  async function runSample() {
    setLoading(true)
    setError("")
    try {
      const res = await fetch(`${API_BASE}/scan/sample?use_ai=${useAI}`, { method: "POST" })
      if (!res.ok) throw new Error(await responseError(res, "Could not run sample analysis"))
      setReport(await res.json())
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed.")
    } finally {
      setLoading(false)
    }
  }

  async function runUpload() {
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      setError("The selected file exceeds the 2 MB upload limit.")
      return
    }
    setLoading(true)
    setError("")
    try {
      const body = new FormData()
      body.append("file", file)
      body.append("use_ai", String(useAI))

      const res = await fetch(`${API_BASE}/scan/upload`, { method: "POST", body })
      if (!res.ok) {
        throw new Error(await responseError(res, "Could not analyze file"))
      }
      setReport(await res.json())
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page" aria-busy={loading}>
      <nav className="nav">
        <div className="brand">
          <div className="brand-mark">A</div>
          <div>
            <strong>APIShield</strong>
            <span>Agent</span>
          </div>
        </div>
        <div className="nav-pill">Portfolio Demo</div>
      </nav>

      <header className="hero">
        <div className="hero-copy">
          <div className="kicker">AGENTIC API SECURITY REVIEW</div>
          <h1>Turn an OpenAPI spec into a prioritized security review.</h1>
          <p>
            APIShield uses a LangGraph workflow to inventory endpoints, create a review plan,
            correlate defensive security signals, and produce an evidence-oriented report.
          </p>
          <div className="hero-actions">
            <button onClick={runSample} disabled={loading}>
              {loading ? "Analyzing..." : "Run Demo Analysis"}
            </button>
            <span className="safe-note">Designed for authorized defensive testing only.</span>
          </div>
        </div>

        <div className="agent-card">
          <div className="agent-top">
            <div>
              <span className="micro">AGENT STATUS</span>
              <strong>{loading ? "Analyzing" : report ? "Completed" : "Ready"}</strong>
            </div>
            <div className={`status-dot ${loading ? "pulse" : ""}`} />
          </div>

          <div className="agent-flow">
            {["Parse API", "Plan Review", "Collect Signals", "Correlate", "Report"].map((step, i) => (
              <div className="flow-row" key={step}>
                <div className={`flow-icon ${report || (loading && i < 2) ? "done" : ""}`}>
                  {report || (loading && i < 2) ? "✓" : i + 1}
                </div>
                <span>{step}</span>
              </div>
            ))}
          </div>
        </div>
      </header>

      <main>
        <section className="workspace">
          <div className="panel scan-panel">
            <div className="panel-head">
              <div>
                <span className="micro">INPUT</span>
                <h2>Start an API Review</h2>
              </div>
            </div>

            <label className="upload">
              <input
                type="file"
                accept=".yaml,.yml,.json"
                onChange={(e) => {
                  setFile(e.target.files?.[0] || null)
                  setError("")
                }}
              />
              <div className="upload-icon">↑</div>
              <strong>{file ? file.name : "Upload OpenAPI specification"}</strong>
              <span>YAML or JSON · 2 MB maximum</span>
            </label>

            <label className="ai-toggle">
              <input
                type="checkbox"
                checked={useAI}
                onChange={(e) => setUseAI(e.target.checked)}
              />
              <div>
                <strong>OpenAI-assisted planning</strong>
                <span>Uses deterministic planning when no API key is configured.</span>
              </div>
            </label>

            <div className="scan-actions">
              <button onClick={runUpload} disabled={!file || loading}>Analyze Upload</button>
              <button className="ghost" onClick={runSample} disabled={loading}>Use Sample Spec</button>
            </div>

            {error && <div className="error" role="alert">{error}</div>}
          </div>

          <div className="panel metrics-panel">
            <span className="micro">OVERVIEW</span>
            <div className="metrics">
              <div className="metric">
                <span>Endpoints</span>
                <strong>{report?.endpoint_count ?? 0}</strong>
              </div>
              <div className="metric">
                <span>Findings</span>
                <strong>{report?.summary.total_findings ?? 0}</strong>
              </div>
              <div className="metric">
                <span>Highest Risk</span>
                <strong>{highest}</strong>
              </div>
              <div className="metric">
                <span>Planning</span>
                <strong className="small-value">{report?.planning_mode ?? "—"}</strong>
              </div>
            </div>

            <div className="plan-box">
              <h3>Agent Plan</h3>
              {report ? (
                <ol>
                  {report.plan.map((step, i) => (
                    <li key={`${step.title}-${i}`}>
                      <div className="plan-title">
                        <span className={severityClass(step.priority)}>{step.priority}</span>
                        <strong>{step.title}</strong>
                      </div>
                      <p>{step.rationale}</p>
                      {step.endpoints.length > 0 && (
                        <div className="plan-endpoints">
                          {step.endpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}
                        </div>
                      )}
                    </li>
                  ))}
                </ol>
              ) : (
                <p>Run a review to generate a prioritized plan.</p>
              )}
            </div>
          </div>
        </section>

        <section className="results-grid">
          <div className="panel trace-panel">
            <div className="panel-head">
              <div>
                <span className="micro">TRACE</span>
                <h2>LangGraph Execution</h2>
              </div>
              {report && <span className="count-pill">{report.timeline.length} nodes</span>}
            </div>

            <div className="timeline">
              {report ? report.timeline.map((item, i) => (
                <div className="timeline-row" key={item.node}>
                  <div className="timeline-node">{i + 1}</div>
                  <div className="timeline-content">
                    <div className="node-heading">
                      <div>
                        <code className="node-id">{item.node}</code>
                        <strong>{item.step}</strong>
                      </div>
                      <span className="completed-pill">{item.status}</span>
                    </div>
                    <span className="node-detail">{item.detail}</span>
                    <div className="tool-list">
                      {item.tool_invocations.map((tool) => (
                        <div className="tool-invocation" key={tool.name}>
                          <div className="tool-icon">T</div>
                          <div>
                            <code>{tool.name}</code>
                            <p>{tool.summary}</p>
                          </div>
                          <span>{tool.status}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )) : (
                <div className="empty">Agent activity will appear here.</div>
              )}
            </div>
          </div>

          <div className="panel findings-panel">
            <div className="panel-head">
              <div>
                <span className="micro">OUTPUT</span>
                <h2>Security Findings</h2>
              </div>
              {report && <span className="count-pill">{report.findings.length} findings</span>}
            </div>

            <div className="findings">
              {report?.findings.length ? report.findings.map((f) => (
                <article className="finding" key={f.id}>
                  <div className="finding-top">
                    <div>
                      <div className="endpoint-row">
                        <span className="method">{f.method}</span>
                        <code>{f.endpoint}</code>
                      </div>
                      <h3>{f.category.replaceAll("-", " ")}</h3>
                    </div>
                    <span className={severityClass(f.severity)}>{f.severity}</span>
                  </div>

                  <div className="confidence-row">
                    <span>Confidence</span>
                    <strong>{Math.round(f.confidence * 100)}%</strong>
                  </div>

                  <div className="confidence-track">
                    <div style={{ width: `${Math.round(f.confidence * 100)}%` }} />
                  </div>

                  <div className="finding-section">
                    <strong>Evidence</strong>
                    <ul>
                      {f.evidence.map((e, i) => <li key={i}>{e}</li>)}
                    </ul>
                  </div>

                  <div className="finding-section">
                    <strong>Recommendation</strong>
                    <p>{f.remediation}</p>
                  </div>

                  <div className="source-row">
                    {f.source_tools.map((s) => <span key={s}>{s}</span>)}
                    <span className="finding-status">{f.status.replaceAll("-", " ")}</span>
                  </div>
                </article>
              )) : (
                <div className="empty">Run an analysis to see findings.</div>
              )}
            </div>

            {report && <div className="disclaimer">{report.disclaimer}</div>}
          </div>
        </section>

        <section className="panel remediation-panel">
          <div className="panel-head">
            <div>
              <span className="micro">FINAL REPORT</span>
              <h2>Remediation Workstreams</h2>
            </div>
            {report && <span className="count-pill">{report.remediation_report.length} priorities</span>}
          </div>

          {report?.remediation_report.length ? (
            <div className="remediation-grid">
              {report.remediation_report.map((item, index) => (
                <article className="remediation-card" key={item.category}>
                  <div className="remediation-rank">{String(index + 1).padStart(2, "0")}</div>
                  <div className="remediation-body">
                    <div className="remediation-heading">
                      <h3>{item.category.replaceAll("-", " ")}</h3>
                      <span className={severityClass(item.severity)}>{item.severity}</span>
                    </div>
                    <p>{item.recommendation}</p>
                    <div className="affected-list">
                      <span>{item.finding_count} {item.finding_count === 1 ? "finding" : "findings"}</span>
                      {item.affected_endpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}
                    </div>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <div className="empty">Run an analysis to generate the final remediation report.</div>
          )}
        </section>
      </main>

      <footer>
        <span>APIShield Agent</span>
        <span>LangGraph · FastAPI · React · OpenAI-ready</span>
      </footer>
    </div>
  )
}
