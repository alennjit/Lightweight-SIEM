import { demoAlerts, demoHistory } from "./demo/demoData";
import type {
  Alert,
  EmailScoreRequest,
  EmailScoreResponse,
  FamilyLink,
  Invite,
  Me,
  ProtectionHistory,
  Role,
} from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

/** True in the public GitHub Pages build (`vite build --mode demo`), which has no backend. */
export const DEMO_MODE = import.meta.env.MODE === "demo";

/** The session cookie is missing or expired — the app shows the sign-in screen. */
export class UnauthorizedError extends Error {}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    // Sends the httpOnly session cookie. The token is never visible to this code.
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    let detail = response.status === 401 ? "Please sign in." : `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // non-JSON error body — keep the generic message
    }
    // Keep the server's wording (e.g. "That email and password don't match.").
    throw response.status === 401 ? new UnauthorizedError(detail) : new Error(detail);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function personQuery(personId: number | null, extra: Record<string, string> = {}): string {
  const params = new URLSearchParams(extra);
  if (personId !== null) params.set("person_id", String(personId));
  const query = params.toString();
  return query ? `?${query}` : "";
}

// --- Auth ---------------------------------------------------------------

export function fetchMe(): Promise<Me> {
  return request<Me>("/api/v1/auth/me");
}

export function login(email: string, password: string): Promise<Me> {
  return request<Me>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
}

export function register(email: string, password: string, displayName: string, role: Role): Promise<Me> {
  return request<Me>("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password, display_name: displayName, role }),
  });
}

export function logout(): Promise<void> {
  return request<void>("/api/v1/auth/logout", { method: "POST" });
}

// --- Family links -------------------------------------------------------

export function createInvite(): Promise<Invite> {
  return request<Invite>("/api/v1/family/invites", { method: "POST" });
}

export function redeemInvite(code: string): Promise<FamilyLink> {
  return request<FamilyLink>("/api/v1/family/invites/redeem", { method: "POST", body: JSON.stringify({ code }) });
}

export function fetchLinks(): Promise<FamilyLink[]> {
  return request<FamilyLink[]>("/api/v1/family/links");
}

export function revokeLink(linkId: number): Promise<void> {
  return request<void>(`/api/v1/family/links/${linkId}`, { method: "DELETE" });
}

// --- Data for one protected person ---------------------------------------

export function fetchAlerts(personId: number | null): Promise<Alert[]> {
  if (DEMO_MODE) return Promise.resolve(demoAlerts());
  return request<Alert[]>(`/api/v1/alerts${personQuery(personId)}`);
}

export function fetchHistory(personId: number | null, days = 30): Promise<ProtectionHistory> {
  if (DEMO_MODE) return Promise.resolve(demoHistory());
  return request<ProtectionHistory>(`/api/v1/stats/history${personQuery(personId, { days: String(days) })}`);
}

export function scoreEmail(personId: number | null, payload: EmailScoreRequest): Promise<EmailScoreResponse> {
  return request<EmailScoreResponse>(`/api/v1/emails/score${personQuery(personId)}`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
