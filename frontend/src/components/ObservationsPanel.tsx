import type { Observation } from "../types"
import { titleCase } from "../utils"

function formatValue(observation: Observation) {
  const value = observation.value
  if (observation.category === "https-usage") return value ? "HTTPS enabled" : "HTTP only"
  if (observation.category === "response-size" && typeof value === "number") return `${value.toLocaleString()} bytes`
  if (observation.category === "redirects" && Array.isArray(value)) return value.length ? value.map((item) => JSON.stringify(item)).join("\n") : "No redirects"
  if (value && typeof value === "object") return Object.keys(value as object).length ? JSON.stringify(value, null, 2) : "None observed"
  return value === "" ? "Not reported" : String(value)
}

export function ObservationsPanel({ observations }: { observations: Observation[] }) {
  if (!observations.length) return null
  return (
    <section className="card observations-panel" aria-labelledby="observations-heading">
      <div className="panel-heading-row"><div className="section-heading"><span>PASSIVE EVIDENCE</span><h2 id="observations-heading">Observed Response Metadata</h2></div><span className="count-badge">{observations.length}</span></div>
      <div className="observation-grid">{observations.map((observation, index) => <article key={`${observation.category}-${index}`}><span>{titleCase(observation.category)}</span><pre>{formatValue(observation)}</pre><small>{observation.url}</small></article>)}</div>
    </section>
  )
}
