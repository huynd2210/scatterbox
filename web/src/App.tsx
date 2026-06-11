// App shell: routes between the three top-level screens by daemon state —
// setup wizard (uninitialized) → unlock (locked) → tabbed explorer — and
// fans WebSocket events out to whichever views care.
import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { FileBrowser } from "./components/FileBrowser";
import { Providers } from "./components/Providers";
import { SetupWizard } from "./components/Setup";
import { Transfers } from "./components/Transfers";
import type { DaemonEvent, Status } from "./types";
import { useDaemonEvents } from "./ws";

type Tab = "files" | "transfers" | "providers";

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [tab, setTab] = useState<Tab>("files");
  // bumped whenever the tree changed server-side; FileBrowser re-lists on it
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastEvent, setLastEvent] = useState<DaemonEvent | null>(null);

  const refreshStatus = useCallback(() => {
    api.status().then(setStatus).catch(() => setStatus(null));
  }, []);

  useEffect(refreshStatus, [refreshStatus]);

  useDaemonEvents((event) => {
    setLastEvent(event);
    if (
      event.type === "files-changed" ||
      (event.type === "job" && (event.state === "done" || event.state === "failed"))
    ) {
      setRefreshKey((k) => k + 1);
      refreshStatus();
    }
  });

  if (status === null) {
    return (
      <div className="center-screen">
        <h1>scatterbox</h1>
        <p className="muted">daemon unreachable — is `scatterbox daemon` running?</p>
        <button onClick={refreshStatus}>retry</button>
      </div>
    );
  }
  if (!status.initialized) {
    return <SetupWizard onDone={refreshStatus} />;
  }
  if (status.locked) {
    return <UnlockScreen onUnlocked={refreshStatus} />;
  }

  const durability =
    status.chunks_total === 0
      ? 100
      : Math.floor((status.chunks_at_floor / status.chunks_total) * 100);

  return (
    <div className="app">
      <header>
        <h1>scatterbox</h1>
        <nav>
          {(["files", "transfers", "providers"] as Tab[]).map((t) => (
            <button
              key={t}
              className={tab === t ? "tab active" : "tab"}
              onClick={() => setTab(t)}
            >
              {t}
              {t === "transfers" && status.jobs_pending > 0 && (
                <span className="badge">{status.jobs_pending}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="header-right">
          <span
            className={durability === 100 ? "durability ok" : "durability warn"}
            title="chunks at full replica target"
          >
            durability {durability}%
          </span>
          <span className="muted">{status.files} files</span>
          <button
            className="ghost"
            onClick={() => api.lock().then(refreshStatus)}
            title="forget the master key"
          >
            lock
          </button>
        </div>
      </header>
      <main>
        {tab === "files" && <FileBrowser refreshKey={refreshKey} />}
        {tab === "transfers" && <Transfers lastEvent={lastEvent} />}
        {tab === "providers" && <Providers refreshKey={refreshKey} />}
      </main>
    </div>
  );
}

/** Passphrase prompt shown while the daemon is locked (423s elsewhere). */
function UnlockScreen({ onUnlocked }: { onUnlocked: () => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    api
      .unlock(passphrase)
      .then(onUnlocked)
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };

  return (
    <div className="center-screen">
      <h1>scatterbox</h1>
      <form onSubmit={submit} className="unlock">
        <input
          type="password"
          placeholder="master passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          autoFocus
        />
        <button disabled={busy || passphrase === ""}>
          {busy ? "deriving key…" : "unlock"}
        </button>
        {error && <p className="error">{error}</p>}
      </form>
      <p className="muted small">
        The key is derived in the daemon and held in memory only.
      </p>
    </div>
  );
}
