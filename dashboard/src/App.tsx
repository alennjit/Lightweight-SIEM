import { useState } from "react";
import { AlertList } from "./components/AlertList";
import { TestEmailForm } from "./components/TestEmailForm";
import "./App.css";

function App() {
  const [refreshKey, setRefreshKey] = useState(0);

  return (
    <div className="app">
      <header className="app__header">
        <h1>Lightweight SIEM</h1>
        <p className="subtitle">Monitor dashboard — flagged messages for your protected person</p>
      </header>
      <main className="app__main">
        <section className="app__alerts">
          <h2>Recent alerts</h2>
          <AlertList refreshKey={refreshKey} />
        </section>
        <section className="app__form">
          <TestEmailForm onScored={() => setRefreshKey((key) => key + 1)} />
        </section>
      </main>
    </div>
  );
}

export default App;
