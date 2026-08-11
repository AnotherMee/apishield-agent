import type { ScanReport } from "./types"

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"

export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024

async function responseError(response: Response, fallback: string): Promise<Error> {
  const data = await response.json().catch(() => null) as { detail?: string | Array<{ msg?: string }> } | null
  const detail = Array.isArray(data?.detail)
    ? data.detail.map((item) => item.msg).filter(Boolean).join(" ")
    : data?.detail
  return new Error(detail || `${fallback} (${response.status})`)
}

async function request<T>(url: string, init: RequestInit, fallback: string): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}${url}`, init)
  } catch {
    throw new Error("APIShield could not reach the backend. Confirm that the API service is running.")
  }
  if (!response.ok) throw await responseError(response, fallback)
  return response.json() as Promise<T>
}

export function runPassiveDiscovery(target: string, useAI: boolean): Promise<ScanReport> {
  return request(
    "/discovery/passive",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, use_ai: useAI }),
    },
    "Passive discovery could not be completed",
  )
}

export function runSampleScan(useAI: boolean): Promise<ScanReport> {
  return request(`/scan/sample?use_ai=${useAI}`, { method: "POST" }, "Could not run sample analysis")
}

export function runUploadScan(file: File, useAI: boolean): Promise<ScanReport> {
  const body = new FormData()
  body.append("file", file)
  body.append("use_ai", String(useAI))
  return request("/scan/upload", { method: "POST", body }, "Could not analyze the OpenAPI file")
}
