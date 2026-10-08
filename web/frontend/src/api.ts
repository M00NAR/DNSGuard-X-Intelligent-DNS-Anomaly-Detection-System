import type { AnalysisResult } from "./types";

// In dev (Vite on :5173) talk to the API on :8000; in production the backend
// serves this bundle, so same-origin relative URLs work.
const BASE = import.meta.env.DEV ? "http://localhost:8000" : "";

async function handle(res: Response): Promise<AnalysisResult> {
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return (await res.json()) as AnalysisResult;
}

export async function analyzeSample(signal?: AbortSignal): Promise<AnalysisResult> {
  return handle(await fetch(`${BASE}/api/sample`, { signal }));
}

export async function analyzeFile(file: File, signal?: AbortSignal): Promise<AnalysisResult> {
  const form = new FormData();
  form.append("file", file);
  return handle(await fetch(`${BASE}/api/analyze`, { method: "POST", body: form, signal }));
}
