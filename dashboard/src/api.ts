import { demoAlerts, demoHistory } from "./demo/demoData";
import type { Alert, EmailScoreRequest, EmailScoreResponse, ProtectionHistory } from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

/** True in the public GitHub Pages build (`vite build --mode demo`), which has no backend. */
export const DEMO_MODE = import.meta.env.MODE === "demo";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Request to ${path} failed (${response.status}): ${detail}`);
  }
  return response.json() as Promise<T>;
}

export function fetchAlerts(): Promise<Alert[]> {
  if (DEMO_MODE) return Promise.resolve(demoAlerts());
  return request<Alert[]>("/api/v1/alerts");
}

export function fetchHistory(days = 30): Promise<ProtectionHistory> {
  if (DEMO_MODE) return Promise.resolve(demoHistory());
  return request<ProtectionHistory>(`/api/v1/stats/history?days=${days}`);
}

export function scoreEmail(payload: EmailScoreRequest): Promise<EmailScoreResponse> {
  return request<EmailScoreResponse>("/api/v1/emails/score", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
