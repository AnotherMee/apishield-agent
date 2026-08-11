import type { ScanReport } from "../types"

const pipeline = [
  ["01", "Analyze Input", "URL / OpenAPI"],
  ["02", "AI Planning", "OpenAI + deterministic fallback"],
  ["03", "LangGraph", "Stateful workflow orchestration"],
  ["04", "Findings", "Evidence + Potential Impact"],
  ["05", "Remediation", "AI-assisted guidance"],
]

type Props = { report: ScanReport | null; backendStatus: "not-checked" | "checking" | "online" | "unavailable" }

export function Sidebar({ report, backendStatus }: Props) {
  const backendLabel = backendStatus.replace("-", " ").replace(/^./, (letter) => letter.toUpperCase())
  const openAIStatus = !report ? "Not checked" : report.planning_mode.toLowerCase().includes("openai") ? "Connected" : "Fallback"
  const graphStatus = backendStatus === "checking" ? "Running" : report ? "Complete" : "Ready"

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <strong>APISHIELD</strong>
        <span>AGENTIC API SECURITY REVIEW</span>
      </div>
      <section className="pipeline" aria-labelledby="pipeline-heading">
        <h2 id="pipeline-heading">CURRENT PIPELINE</h2>
        <div className="pipeline-list">
          {pipeline.map(([number, title, description]) => (
            <div className="pipeline-step" key={number}>
              <span>{number}</span>
              <div><strong>{title}</strong><small>{description}</small></div>
            </div>
          ))}
        </div>
      </section>
      <section className="system-status" aria-labelledby="status-heading">
        <h2 id="status-heading">SYSTEM STATUS</h2>
        <dl>
          <div><dt>Backend</dt><dd className={backendStatus === "online" ? "status-success" : ""}>{backendLabel}</dd></div>
          <div><dt>OpenAI</dt><dd className={openAIStatus === "Connected" ? "status-success" : openAIStatus === "Fallback" ? "status-gold" : ""}>{openAIStatus}</dd></div>
          <div><dt>Analysis Mode</dt><dd>Passive</dd></div>
          <div><dt>LangGraph</dt><dd className={graphStatus === "Complete" ? "status-success" : ""}>{graphStatus}</dd></div>
        </dl>
      </section>
      <div className="boundary-card">
        <span>PASSIVE DEFENSIVE ANALYSIS ONLY</span>
        <p>No exploitation.<br />No active attacks.<br />No credential testing.</p>
      </div>
    </aside>
  )
}
