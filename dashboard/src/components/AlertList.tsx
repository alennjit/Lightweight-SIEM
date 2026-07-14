import { useEffect, useState } from "react";
import { fetchAlerts } from "../api";
import type { Alert } from "../types";

function scoreTier(score: number): "low" | "medium" | "high" {
  if (score >= 8) return "high";
  if (score >= 5) return "medium";
  return "low";
}

export function AlertList({ refreshKey }: { refreshKey: number }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchAlerts()
      .then((data) => {
        if (!cancelled) setAlerts(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unknown error");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  if (loading) return <p>Loading alerts…</p>;
  if (error) return <p className="error">Failed to load alerts: {error}</p>;
  if (alerts.length === 0) {
    return <p className="empty-state">No alerts yet. Try scoring a test email below.</p>;
  }

  return (
    <ul className="alert-list">
      {alerts.map((alert) => (
        <li key={alert.id} className={`alert-card alert-card--${scoreTier(alert.score)}`}>
          <div className="alert-card__header">
            <span className={`score-badge score-badge--${scoreTier(alert.score)}`}>{alert.score}/10</span>
            {/* Subject/sender/links are attacker-influenced content — always rendered as
                plain text via JSX interpolation, never as HTML. See ~/.claude/skills/frontend-design. */}
            <span className="alert-card__subject">{alert.subject}</span>
          </div>
          <p className="alert-card__sender">From: {alert.sender_domain}</p>
          <p className="alert-card__rationale">{alert.rationale}</p>
          {alert.links.length > 0 && (
            <ul className="alert-card__links">
              {alert.links.map((link, i) => (
                <li key={i}>
                  <code>{link}</code> <span className="link-warning">(not a live link — flagged content)</span>
                </li>
              ))}
            </ul>
          )}
          <p className="alert-card__time">{new Date(alert.created_at).toLocaleString()}</p>
        </li>
      ))}
    </ul>
  );
}
