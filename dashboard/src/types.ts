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
