import { useEffect, useState } from "react";
import { AlertList } from "./components/AlertList";
import { StatTiles } from "./components/StatTiles";
import { TestEmailForm } from "./components/TestEmailForm";
import { fetchAlerts } from "./api";
import type { Alert } from "./types";
import "./App.css";

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

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

  return (
    <div className="app">
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

      <main className="app__main">
        <StatTiles alerts={alerts} loading={loading} />

        <section className="app__alerts" aria-labelledby="alerts-heading">
          <h2 id="alerts-heading">Recent alerts</h2>
          <AlertList alerts={alerts} loading={loading} error={error} />
        </section>

        <details className="dev-tools">
          <summary>Developer test tool</summary>
          <p className="dev-tools__hint">
            For verifying the detection engine during development — not part of the product a
            real monitor would see.
          </p>
          <TestEmailForm onScored={() => setRefreshKey((key) => key + 1)} />
        </details>
      </main>
    </div>
  );
}

export default App;
