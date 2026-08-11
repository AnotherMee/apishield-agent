const navigation = ["Overview", "New Review", "Reports", "History", "Settings"]

export function Sidebar() {
  return (
    <aside className="sidebar">
      <a className="sidebar-brand" href="#top" aria-label="APIShield overview">
        <strong>APISHIELD</strong>
        <span>AGENTIC API SECURITY REVIEW</span>
      </a>
      <nav className="sidebar-nav" aria-label="Primary navigation">
        {navigation.map((item, index) => (
          <a className={index === 1 ? "active" : ""} href={index === 1 ? "#new-review" : index === 2 ? "#reports" : "#top"} key={item}>
            <span className="nav-index">0{index + 1}</span>{item}
          </a>
        ))}
      </nav>
      <div className="boundary-card">
        <span>PASSIVE DEFENSIVE ANALYSIS ONLY</span>
        <p>No exploitation.<br />No active attacks.<br />Just insights that help you secure.</p>
      </div>
    </aside>
  )
}
