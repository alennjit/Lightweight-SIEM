import type { Alert } from "../types";

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 4.5 5.5v6c0 5.2 3.4 9.4 7.5 10.5 4.1-1.1 7.5-5.3 7.5-10.5v-6L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function AlertTriangleIcon() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" aria-hidden="true">
      <path
        d="M12 4 2.5 20h19L12 4Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="M12 10v4.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="12" cy="17.3" r="0.9" fill="currentColor" />
    </svg>
  );
}

function EyeIcon() {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" aria-hidden="true">
      <path
        d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="2.5" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

export function StatTiles({ alerts, loading }: { alerts: Alert[]; loading: boolean }) {
  const attentionNow = alerts.filter((a) => a.score >= 8).length;
  const worthALook = alerts.filter((a) => a.score >= 5 && a.score < 8).length;

  return (
    <section className="stat-tiles" aria-label="Alert summary">
      <div className="stat-tile stat-tile--brand">
        <span className="stat-tile__icon">
          <ShieldIcon />
        </span>
        <span className="stat-tile__value">{loading ? "–" : alerts.length}</span>
        <span className="stat-tile__label">Total flagged</span>
      </div>
      <div className="stat-tile stat-tile--critical">
        <span className="stat-tile__icon">
          <AlertTriangleIcon />
        </span>
        <span className="stat-tile__value">{loading ? "–" : attentionNow}</span>
        <span className="stat-tile__label">Needs attention now</span>
      </div>
      <div className="stat-tile stat-tile--warning">
        <span className="stat-tile__icon">
          <EyeIcon />
        </span>
        <span className="stat-tile__value">{loading ? "–" : worthALook}</span>
        <span className="stat-tile__label">Worth a look</span>
      </div>
    </section>
  );
}
