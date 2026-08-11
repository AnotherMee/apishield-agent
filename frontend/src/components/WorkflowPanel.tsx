import type { ReviewStep, TimelineItem } from "../types"
import { severityClass } from "../utils"

export function WorkflowPanel({ timeline, plan }: { timeline: TimelineItem[]; plan: ReviewStep[] }) {
  return (
    <section className="card workflow-panel" aria-labelledby="workflow-heading">
      <div className="section-heading"><span>LANGGRAPH</span><h2 id="workflow-heading">LangGraph Execution</h2></div>
      <div className="timeline">
        {timeline.map((item, index) => (
          <article className="timeline-row" key={`${item.node}-${index}`}>
            <div className="timeline-index">{index + 1}</div>
            <div className="timeline-copy">
              <div className="timeline-title"><strong>{item.step}</strong><span>✓ {item.status}</span></div>
              <p>{item.detail}</p>
              {item.tool_invocations.map((tool) => (
                <div className="tool-row" key={tool.name}>
                  <code>{tool.name}</code><span>{tool.summary}</span>
                </div>
              ))}
            </div>
          </article>
        ))}
      </div>
      <details className="agent-plan">
        <summary>View agent plan <span>{plan.length} steps</span></summary>
        <ol>{plan.map((step, index) => <li key={`${step.title}-${index}`}><div><span className={severityClass(step.priority)}>{step.priority}</span><strong>{step.title}</strong></div><p>{step.rationale}</p></li>)}</ol>
      </details>
    </section>
  )
}
