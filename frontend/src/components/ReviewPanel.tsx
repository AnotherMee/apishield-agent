import type { FormEvent } from "react"

export type ReviewInput = "url" | "openapi"

type Props = {
  mode: ReviewInput
  target: string
  file: File | null
  useAI: boolean
  loading: boolean
  error: string
  onModeChange: (mode: ReviewInput) => void
  onTargetChange: (target: string) => void
  onFileChange: (file: File | null) => void
  onUseAIChange: (enabled: boolean) => void
  onUrlSubmit: () => void
  onUploadSubmit: () => void
  onSampleSubmit: () => void
}

export function ReviewPanel(props: Props) {
  function submit(event: FormEvent) {
    event.preventDefault()
    props.onUrlSubmit()
  }

  return (
    <section className="card review-card" aria-labelledby="review-heading">
      <div className="section-heading"><span>NEW REVIEW</span><h2 id="review-heading">Start a Security Review</h2></div>
      <fieldset className="input-tabs">
        <legend className="sr-only">Security review input</legend>
        <label><input type="radio" name="review-input" checked={props.mode === "url"} onChange={() => props.onModeChange("url")} /><span>Analyze URL</span></label>
        <label><input type="radio" name="review-input" checked={props.mode === "openapi"} onChange={() => props.onModeChange("openapi")} /><span>Analyze OpenAPI</span></label>
      </fieldset>

      {props.mode === "url" ? (
        <form className="target-form" onSubmit={submit}>
          <label htmlFor="review-target">Target URL</label>
          <div className="url-row">
            <input id="review-target" type="url" inputMode="url" placeholder="https://api.example.com" value={props.target} onChange={(event) => props.onTargetChange(event.target.value)} required />
            <button type="submit" disabled={props.loading}>{props.loading ? "Reviewing…" : "Start Review →"}</button>
          </div>
          <p className="boundary-copy">Passive observation of public endpoints and metadata.<br />No exploitation, fuzzing, or active attacks.</p>
        </form>
      ) : (
        <div className="openapi-workspace">
          <label className="upload">
            <input type="file" accept=".yaml,.yml,.json" onChange={(event) => props.onFileChange(event.target.files?.[0] || null)} />
            <span className="upload-mark" aria-hidden="true">↑</span>
            <strong>{props.file ? props.file.name : "Upload OpenAPI specification"}</strong>
            <small>YAML or JSON · 2 MB maximum · Static metadata review</small>
          </label>
          <div className="review-actions">
            <button type="button" onClick={props.onUploadSubmit} disabled={!props.file || props.loading}>{props.loading ? "Reviewing…" : "Analyze Upload →"}</button>
            <button type="button" className="secondary-button" onClick={props.onSampleSubmit} disabled={props.loading}>Run Sample</button>
          </div>
        </div>
      )}

      <label className="ai-toggle">
        <input type="checkbox" checked={props.useAI} onChange={(event) => props.onUseAIChange(event.target.checked)} />
        <span className="toggle-track" aria-hidden="true"><span /></span>
        <span><strong>Use AI-assisted planning</strong><small>Deterministic fallback remains available.</small></span>
      </label>
      {props.error && <div className="error" role="alert">{props.error}</div>}
    </section>
  )
}
