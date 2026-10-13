import type { Alert } from "../types";

type Tier = "low" | "medium" | "high";

const TIER_LABEL: Record<Tier, string> = {
  high: "Act now",
  medium: "Take a look",
  low: "Looks fine",
};

function scoreTier(score: number): Tier {
  if (score >= 8) return "high";
  if (score >= 5) return "medium";
  return "low";
}

function relativeTime(iso: string): string {
  const date = new Date(iso);
  const diffMs = Date.now() - date.getTime();
  const diffMin = Math.round(diffMs / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleDateString();
}

export function AlertList({
  alerts,
  loading,
  error,
}: {
  alerts: Alert[];
  loading: boolean;
  error: string | null;
}) {
  if (loading) return <p className="loading-state">Loading alerts…</p>;
  if (error) return <p className="error">Failed to load alerts: {error}</p>;
  if (alerts.length === 0) {
    return (
      <div className="empty-state">
        <p className="empty-state__title">Nothing flagged</p>
        <p className="empty-state__hint">
          You&rsquo;ll see something here the moment a risky message shows up.
        </p>
      </div>
    );
  }

  return (
    <ul className="alert-list">
      {alerts.map((alert) => {
        const tier = scoreTier(alert.score);
        return (
          <li key={alert.id} className={`alert-card alert-card--${tier}`}>
            <div className="alert-card__header">
              <span className={`score-badge score-badge--${tier}`}>
                {TIER_LABEL[tier]}
                <span className="score-badge__score">{alert.score}/10</span>
              </span>
              {/* Subject/sender/links are attacker-influenced content — always rendered as
                  plain text via JSX interpolation, never as HTML. See CONTRIBUTING.md's
                  "Frontend Security" section. */}
              <span className="alert-card__subject">{alert.subject}</span>
            </div>
            <p className="alert-card__sender">From: {alert.sender_domain}</p>
            <p className="alert-card__rationale">{alert.rationale}</p>
            {alert.links.length > 0 && (
              <ul className="alert-card__links">
                {alert.links.map((link, i) => (
                  <li key={i}>
                    <code>{link}</code>{" "}
                    <span className="link-warning">(not a live link — flagged content)</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="alert-card__time">{relativeTime(alert.created_at)}</p>
          </li>
        );
      })}
    </ul>
  );
}
