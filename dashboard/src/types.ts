export interface Alert {
  id: number;
  sender_domain: string;
  subject: string;
  links: string[];
  score: number;
  rationale: string;
  created_at: string;
}

export interface EmailScoreRequest {
  sender_domain: string;
  subject: string;
  links: string[];
  body?: string;
  sender_display_name?: string;
}

export interface EmailScoreResponse {
  score: number;
  flagged: boolean;
  rationale: string;
  signals: string[];
  alert_id: number | null;
}

export interface DailyCount {
  date: string; // YYYY-MM-DD (UTC)
  checked: number;
  caught: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}

/** Mirrors the backend's ProtectionHistoryOut — aggregates only, never message content. */
export interface ProtectionHistory {
  days: number;
  first_scan_at: string | null;
  emails_checked: number;
  threats_caught: number;
  high_risk: number;
  links_flagged: number;
  daily: DailyCount[];
  categories: CategoryCount[];
}

export type Role = "protected" | "monitor";

export interface Person {
  id: number;
  display_name: string;
}

/** The signed-in user. Never includes credentials — the session lives in an httpOnly cookie. */
export interface Me {
  id: number;
  email: string;
  display_name: string;
  role: Role;
  people: Person[]; // protected people this user can view (just themselves, if protected)
}

export interface Invite {
  code: string;
  expires_at: string;
}

export interface FamilyLink {
  id: number;
  person_id: number; // the other person on the link
  display_name: string;
  role: Role;
  created_at: string;
}
