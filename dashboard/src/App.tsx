import { useCallback, useEffect, useState, type ReactNode } from "react";
import { AlertList } from "./components/AlertList";
import { AuthScreen } from "./components/AuthScreen";
import { FamilyPanel, RedeemInviteForm } from "./components/FamilyPanel";
import { ProtectionHistory } from "./components/ProtectionHistory";
import { StatTiles } from "./components/StatTiles";
import { TestEmailForm } from "./components/TestEmailForm";
import { DEMO_MODE, UnauthorizedError, fetchAlerts, fetchHistory, fetchMe, logout } from "./api";
import type { Alert, Me, ProtectionHistory as History } from "./types";
import "./App.css";

type Tab = "alerts" | "history" | "family";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown error";
}

function BrandHeader({ children }: { children?: ReactNode }) {
  return (
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
      {children}
    </header>
  );
}

function Dashboard({ me, onSignedOut, onMeChanged }: { me: Me | null; onSignedOut: () => void; onMeChanged: () => void }) {
  const [tab, setTab] = useState<Tab>("alerts");
  const [personId, setPersonId] = useState<number | null>(me?.people[0]?.id ?? null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [history, setHistory] = useState<History | null>(null);
  const [loading, setLoading] = useState(true);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const people = me?.people ?? [];
  const isMonitor = me?.role === "monitor";
  const viewed = people.find((person) => person.id === personId) ?? null;
  const hasPerson = DEMO_MODE || viewed !== null;

  // Keep the selection valid when links change (e.g. someone removed you).
  useEffect(() => {
    if (!me) return;
    if (!me.people.some((person) => person.id === personId)) setPersonId(me.people[0]?.id ?? null);
  }, [me, personId]);

  useEffect(() => {
    if (!hasPerson) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    Promise.allSettled([fetchAlerts(personId), fetchHistory(personId)])
      .then(([alertsResult, historyResult]) => {
        if (cancelled) return;
        for (const result of [alertsResult, historyResult]) {
          if (result.status === "rejected" && result.reason instanceof UnauthorizedError) {
            onSignedOut();
            return;
          }
        }
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
  }, [personId, refreshKey, hasPerson, onSignedOut]);

  async function handleSignOut() {
    try {
      await logout();
    } finally {
      onSignedOut();
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "alerts", label: "Recent alerts" },
    { id: "history", label: "Protection history" },
    ...(DEMO_MODE ? [] : [{ id: "family" as Tab, label: "Family" }]),
  ];

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
      <BrandHeader>
        {me && (
          <div className="account">
            <span className="account__name">{me.display_name}</span>
            <span className="account__role">{isMonitor ? "Family member" : "Protected"}</span>
            <button type="button" className="button-quiet" onClick={handleSignOut}>
              Sign out
            </button>
          </div>
        )}
      </BrandHeader>

      {isMonitor && people.length > 0 && (
        <div className="viewing">
          {people.length === 1 ? (
            <p className="viewing__label">
              Watching out for <strong>{people[0].display_name}</strong>
            </p>
          ) : (
            <label className="viewing__label">
              Watching out for{" "}
              <select value={personId ?? ""} onChange={(e) => setPersonId(Number(e.target.value))}>
                {people.map((person) => (
                  <option key={person.id} value={person.id}>
                    {person.display_name}
                  </option>
                ))}
              </select>
            </label>
          )}
        </div>
      )}

      <nav className="tabs" role="tablist" aria-label="Dashboard sections">
        {tabs.map(({ id, label }) => (
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
        {tab === "family" && me ? (
          <div className="app__panel" role="tabpanel" id="panel-family" aria-labelledby="tab-family">
            <FamilyPanel me={me} onLinksChanged={onMeChanged} />
          </div>
        ) : !hasPerson ? (
          <div className="app__panel" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
            <section className="history__panel onboarding" aria-labelledby="onboarding-heading">
              <h3 id="onboarding-heading">Link to someone to get started</h3>
              <p className="history__panel-hint">
                Ask the person you're watching out for to create an invite code in their account
                (Family → Create an invite code), then enter it here.
              </p>
              <RedeemInviteForm onLinked={onMeChanged} />
            </section>
          </div>
        ) : tab === "alerts" ? (
          <div className="app__panel" role="tabpanel" id="panel-alerts" aria-labelledby="tab-alerts">
            <StatTiles alerts={alerts} loading={loading} />
            <section className="app__alerts" aria-label="Recent alerts">
              <AlertList alerts={alerts} loading={loading} error={alertsError} />
            </section>
            {!DEMO_MODE && (
              <details className="dev-tools">
                <summary>Developer test tool</summary>
                <p className="dev-tools__hint">
                  For verifying the detection engine during development — scores a test email into{" "}
                  {viewed ? `${viewed.display_name}'s` : "this"} history. Not part of the product a real
                  monitor would see.
                </p>
                <TestEmailForm personId={personId} onScored={() => setRefreshKey((key) => key + 1)} />
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

function App() {
  // undefined = still checking the session; null = signed out.
  const [me, setMe] = useState<Me | null | undefined>(DEMO_MODE ? null : undefined);

  const refreshMe = useCallback(() => {
    fetchMe()
      .then(setMe)
      .catch(() => setMe(null));
  }, []);
  const signedOut = useCallback(() => setMe(null), []);

  useEffect(() => {
    if (!DEMO_MODE) refreshMe();
  }, [refreshMe]);

  if (DEMO_MODE) return <Dashboard me={null} onSignedOut={signedOut} onMeChanged={refreshMe} />;
  if (me === undefined) {
    return (
      <div className="app">
        <p className="loading-state">Loading…</p>
      </div>
    );
  }
  if (me === null) {
    return (
      <div className="app">
        <BrandHeader />
        <AuthScreen onSignedIn={setMe} />
      </div>
    );
  }
  // key: a different account gets a completely fresh dashboard state.
  return <Dashboard key={me.id} me={me} onSignedOut={signedOut} onMeChanged={refreshMe} />;
}

export default App;
