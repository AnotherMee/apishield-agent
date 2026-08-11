const steps = [
  ["01", "AI-assisted planning", "Prioritize the review with observable fallback."],
  ["02", "Passive security signals", "Inspect ordinary responses and supplied metadata."],
  ["03", "Finding correlation", "Normalize related evidence into clear findings."],
  ["04", "AI remediation guidance", "Turn review signals into actionable guidance."],
]

export function HowItWorks() {
  return (
    <aside className="card how-card" aria-labelledby="how-heading">
      <div className="section-heading"><span>PROCESS</span><h2 id="how-heading">How it works</h2></div>
      <div className="how-list">
        {steps.map(([number, title, description]) => (
          <div className="how-row" key={title}>
            <span className="line-icon" aria-hidden="true">{number}</span>
            <div><strong>{title}</strong><p>{description}</p></div>
          </div>
        ))}
      </div>
    </aside>
  )
}
