import { useEffect, useState } from "react";
import { AlertList } from "./components/AlertList";
import { ProtectionHistory } from "./components/ProtectionHistory";
import { StatTiles } from "./components/StatTiles";
import { TestEmailForm } from "./components/TestEmailForm";
import { DEMO_MODE, fetchAlerts, fetchHistory } from "./api";
import type { Alert, ProtectionHistory as History } from "./types";
import "./App.css";

type Tab = "alerts" | "history";

const TABS: { id: Tab; label: string }[] = [
  { id: "alerts", label: "Recent alerts" },
  { id: "history", label: "Protection history" },
];

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown error";
}

function App() {
  const [tab, setTab] = useState<Tab>("alerts");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [history, setHistory] = useState<History | null>(null);
  const [loading, setLoading] = useState(true);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.allSettled([fetchAlerts(), fetchHistory()])
      .then(([alertsResult, historyResult]) => {
        if (cancelled) return;
        if (alertsResult.status === "fulfilled") {
          setAlerts(alertsResult.value);
          setAlertsError(null);
        } else {
          setAlertsError(errorMessage(alertsResult.reason));
        }
        if (historyResult.status === "fulfilled") {
          setHistory(historyResult.value);
          setHistoryError(null);
        } else {
          setHistoryError(errorMessage(historyResult.reason));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return (
    <div className="app">
      {DEMO_MODE && (
        <p className="demo-banner" role="note">
          <strong>Demo</strong> &mdash; sample data only. The messages are fictional; every score and
          explanation is real output from the detection engine. Daily email volumes in the history
          are illustrative.{" "}
          <a href="https://github.com/alennjit/Lightweight-SIEM">View the source on GitHub</a>
        </p>
      )}
      <header className="app__header">
        <div className="brand">
          <span className="brand__icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none">
              <path
                d="M12 2.5 4.5 5.5v6c0 5.2 3.4 9.4 7.5 10.5 4.1-1.1 7.5-5.3 7.5-10.5v-6L12 2.5Z"
                fill="var(--brand-tint)"
                stroke="var(--brand)"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path
                d="M8.7 12.2 11 14.5l4.3-4.7"
                stroke="var(--teal)"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <div>
            <h1>Lightweight SIEM</h1>
            <p className="subtitle">Watching out for the people you care about</p>
          </div>
        </div>
      </header>

      <nav className="tabs" role="tablist" aria-label="Dashboard sections">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            role="tab"
            id={`tab-${id}`}
            aria-selected={tab === id}
            aria-controls={`panel-${id}`}
            className={tab === id ? "tabs__tab is-active" : "tabs__tab"}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      <main className="app__main">
        {tab === "alerts" ? (
          <div className="app__panel" role="tabpanel" id="panel-alerts" aria-labelledby="tab-alerts">
            <StatTiles alerts={alerts} loading={loading} />

            <section className="app__alerts" aria-label="Recent alerts">
              <AlertList alerts={alerts} loading={loading} error={alertsError} />
            </section>

            {!DEMO_MODE && (
              <details className="dev-tools">
                <summary>Developer test tool</summary>
                <p className="dev-tools__hint">
                  For verifying the detection engine during development — not part of the product a
                  real monitor would see.
                </p>
                <TestEmailForm onScored={() => setRefreshKey((key) => key + 1)} />
              </details>
            )}
          </div>
        ) : (
          <div className="app__panel" role="tabpanel" id="panel-history" aria-labelledby="tab-history">
            <ProtectionHistory history={history} loading={loading} error={historyError} />
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
