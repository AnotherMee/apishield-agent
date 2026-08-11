import { useState } from "react"
import { MAX_UPLOAD_BYTES, runPassiveDiscovery, runSampleScan, runUploadScan } from "./api"
import { FindingsPanel } from "./components/FindingsPanel"
import { Hero } from "./components/Hero"
import { HowItWorks } from "./components/HowItWorks"
import { MetricsPanel } from "./components/MetricsPanel"
import { ObservationsPanel } from "./components/ObservationsPanel"
import { RemediationPanel } from "./components/RemediationPanel"
import { ReviewPanel, type ReviewInput } from "./components/ReviewPanel"
import { Sidebar } from "./components/Sidebar"
import { WorkflowPanel } from "./components/WorkflowPanel"
import type { ScanReport } from "./types"

function isValidHttpUrl(value: string) {
  try {
    const url = new URL(value)
    return url.protocol === "http:" || url.protocol === "https:"
  } catch {
    return false
  }
}

export default function App() {
  const [reviewInput, setReviewInput] = useState<ReviewInput>("url")
  const [target, setTarget] = useState("")
  const [file, setFile] = useState<File | null>(null)
  const [useAI, setUseAI] = useState(true)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  async function execute(task: () => Promise<ScanReport>) {
    setLoading(true)
    setError("")
    try {
      setReport(await task())
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The request could not be completed.")
    } finally {
      setLoading(false)
    }
  }

  function startUrlReview() {
    if (!isValidHttpUrl(target)) {
      setError("Enter a valid public URL beginning with http:// or https://.")
      return
    }
    void execute(() => runPassiveDiscovery(target, useAI))
  }

  function startUploadReview() {
    if (!file) return
    if (file.size > MAX_UPLOAD_BYTES) {
      setError("The selected OpenAPI file exceeds the 2 MB upload limit.")
      return
    }
    void execute(() => runUploadScan(file, useAI))
  }

  return (
    <div className="app-shell" aria-busy={loading}>
      <Sidebar />
      <div className="app-main">
        <Hero />
        <main className="content" id="new-review">
          <div className="review-grid">
            <ReviewPanel
              mode={reviewInput}
              target={target}
              file={file}
              useAI={useAI}
              loading={loading}
              error={error}
              onModeChange={(mode) => { setReviewInput(mode); setError("") }}
              onTargetChange={setTarget}
              onFileChange={(nextFile) => { setFile(nextFile); setError("") }}
              onUseAIChange={setUseAI}
              onUrlSubmit={startUrlReview}
              onUploadSubmit={startUploadReview}
              onSampleSubmit={() => void execute(() => runSampleScan(useAI))}
            />
            <HowItWorks />
          </div>

          {loading && <div className="loading-banner" role="status" aria-live="polite"><span />APIShield is processing the security review…</div>}

          {report && (
            <div className="report-stack" id="reports">
              <MetricsPanel report={report} />
              <ObservationsPanel observations={report.observations || []} />
              <div className="analysis-grid">
                <WorkflowPanel timeline={report.timeline} plan={report.plan} />
                <FindingsPanel findings={report.findings} disclaimer={report.disclaimer} />
              </div>
              <RemediationPanel items={report.remediation_report} />
            </div>
          )}
        </main>
        <footer><span>APIShield Agent</span><span>LangGraph · FastAPI · React · OpenAI-ready</span></footer>
      </div>
    </div>
  )
}
