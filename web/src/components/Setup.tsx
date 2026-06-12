import { useEffect, useState } from "react";
import { api } from "../api";
import type { NewProvider, ProviderInfo } from "../types";

/** First-run wizard: set up fresh (vault + providers) or import an existing
 * archive — the same two paths the CLI offers, without leaving the browser. */
export function SetupWizard({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<
    "choice" | "passphrase" | "providers" | "import" | "recover"
  >("choice");

  return (
    <div className="center-screen wide">
      <h1>scatterbox</h1>
      {step === "choice" && (
        <>
          <p className="muted">No archive on this machine yet.</p>
          <div className="choice-cards">
            <button className="choice" onClick={() => setStep("passphrase")}>
              <strong>set up new</strong>
              <span className="muted small">
                choose a passphrase, add storage providers
              </span>
            </button>
            <button className="choice" onClick={() => setStep("import")}>
              <strong>import existing</strong>
              <span className="muted small">
                backup zip, vault + register files — or vault alone to recover
                from provider snapshots
              </span>
            </button>
            <button className="choice" onClick={() => setStep("recover")}>
              <strong>recover with passphrase</strong>
              <span className="muted small">
                no files at all — re-authenticate one provider and pull the
                snapshot scatterbox kept there
              </span>
            </button>
          </div>
        </>
      )}
      {step === "passphrase" && <PassphraseStep onNext={() => setStep("providers")} />}
      {step === "providers" && <ProvidersStep onDone={onDone} />}
      {step === "import" && (
        <ImportStep onDone={onDone} onBack={() => setStep("choice")} />
      )}
      {step === "recover" && (
        <RecoverStep onDone={onDone} onBack={() => setStep("choice")} />
      )}
    </div>
  );
}

/** Wizard import path: backup zip / vault+register / vault-only (which
 * recovers the register from provider snapshots) + passphrase. */
function ImportStep({ onDone, onBack }: { onDone: () => void; onBack: () => void }) {
  const [files, setFiles] = useState<File[]>([]);
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const vaultOnly =
    files.length === 1 && files[0].name.toLowerCase().endsWith(".json");

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    api
      .importBackup(files, passphrase)
      .then(onDone)
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <h2>import an existing archive</h2>
      <p className="muted">
        Pick your <code>scatterbox-backup.zip</code> (or{" "}
        <code>vault.json</code> + register file). <code>vault.json</code> alone
        works too: the register is then recovered from the encrypted snapshots
        scatterbox keeps on your providers.
      </p>
      <form onSubmit={submit} className="unlock">
        <input
          type="file"
          multiple
          accept=".zip,.json,.db,.sbsnap"
          onChange={(e) => setFiles(Array.from(e.target.files ?? []))}
        />
        {vaultOnly && (
          <p className="muted small">
            vault only — will recover the register from provider snapshots
          </p>
        )}
        <input
          type="password"
          placeholder="master passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
        <button disabled={busy || files.length === 0 || passphrase === ""}>
          {busy ? "importing…" : "import"}
        </button>
        <button type="button" className="ghost" onClick={onBack}>
          back
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </>
  );
}

/** Cold recovery: nothing local survives — passphrase + re-auth ONE
 * provider; the register snapshot found there rebuilds everything. */
function RecoverStep({ onDone, onBack }: { onDone: () => void; onBack: () => void }) {
  const [type, setType] = useState("localfs");
  const [root, setRoot] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string[] | null>(null);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    api
      .recover({
        passphrase,
        type,
        root: root || undefined,
        client_id: clientId || undefined,
        client_secret: clientSecret || undefined,
      })
      .then((result) => {
        if (result.pending_reauth.length > 0) {
          setPending(result.pending_reauth); // show the to-do before entering
        } else {
          onDone();
        }
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };

  if (pending !== null) {
    return (
      <>
        <h2>recovered ✓</h2>
        <p className="muted">
          These providers still need their credentials restored (providers
          tab → reauth): <strong>{pending.join(", ")}</strong>
        </p>
        <button onClick={onDone}>open explorer</button>
      </>
    );
  }

  return (
    <>
      <h2>recover with passphrase only</h2>
      <p className="muted">
        Point at any provider that held your data — scatterbox keeps an
        encrypted register snapshot on the most reliable ones. Your
        passphrase decrypts it and everything comes back.
      </p>
      <form onSubmit={submit} className="unlock">
        <select value={type} onChange={(e) => setType(e.target.value)}>
          <option value="localfs">local folder</option>
          <option value="gdrive">Google Drive</option>
          <option value="onedrive">OneDrive</option>
        </select>
        {type === "localfs" ? (
          <input
            placeholder="the provider's folder path"
            value={root}
            onChange={(e) => setRoot(e.target.value)}
          />
        ) : (
          <>
            <input
              placeholder="OAuth client id"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
            />
            {type === "gdrive" && (
              <input
                type="password"
                placeholder="OAuth client secret"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
              />
            )}
            <p className="muted small">
              A consent tab will open in your browser; this form waits until
              you finish there.
            </p>
          </>
        )}
        <input
          type="password"
          placeholder="master passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
        <button
          disabled={busy || passphrase === "" || (type === "localfs" ? !root : !clientId)}
        >
          {busy ? "recovering…" : "recover"}
        </button>
        <button type="button" className="ghost" onClick={onBack}>
          back
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </>
  );
}

/** Wizard step 1: choose + confirm the master passphrase (creates and
 * unlocks the vault; warns there is no recovery). */
function PassphraseStep({ onNext }: { onNext: () => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = confirm !== "" && passphrase !== confirm;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (passphrase !== confirm) return;
    setBusy(true);
    setError(null);
    api
      .init(passphrase)
      .then(onNext)
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <h2>1 · choose a master passphrase</h2>
      <p className="muted">
        It encrypts everything: file keys and provider credentials. It is
        never stored — <strong>there is no recovery if you lose it.</strong>
      </p>
      <form onSubmit={submit} className="unlock">
        <input
          type="password"
          placeholder="master passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          autoFocus
        />
        <input
          type="password"
          placeholder="repeat passphrase"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {mismatch && <p className="error small">passphrases don't match</p>}
        <button disabled={busy || passphrase === "" || passphrase !== confirm}>
          {busy ? "creating vault…" : "create vault"}
        </button>
        {error && <p className="error">{error}</p>}
      </form>
    </>
  );
}

/** Wizard step 2: add storage providers (nudges toward the 3 the default
 * replica floor wants, but allows finishing early). */
function ProvidersStep({ onDone }: { onDone: () => void }) {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);

  const refresh = () => {
    api.providers().then(setProviders).catch(() => {});
  };
  useEffect(refresh, []);

  return (
    <>
      <h2>2 · add storage providers</h2>
      <p className="muted">
        Each chunk is stored on several distinct providers (default floor: 3),
        so add at least 3 — local folders work fine to start; cloud accounts
        can join any time.
      </p>
      {providers.length > 0 && (
        <p>
          {providers.map((p) => (
            <span className="chip" key={p.id}>
              {p.name} ({p.type})
            </span>
          ))}
        </p>
      )}
      <ProviderForm onAdded={refresh} />
      <button
        className={providers.length >= 3 ? "" : "ghost"}
        onClick={onDone}
        title={providers.length < 3 ? "you can add more later" : ""}
      >
        {providers.length >= 3 ? "finish setup" : "finish anyway (add more later)"}
      </button>
    </>
  );
}

/** Add-provider form, shared between the wizard and the providers tab. */
export function ProviderForm({ onAdded }: { onAdded: () => void }) {
  const [type, setType] = useState<NewProvider["type"]>("localfs");
  const [name, setName] = useState("");
  const [root, setRoot] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    api
      .addProvider({
        name,
        type,
        root: root || undefined,
        client_id: clientId || undefined,
        client_secret: clientSecret || undefined,
      })
      .then(() => {
        setName("");
        setRoot("");
        onAdded();
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setBusy(false));
  };

  return (
    <form onSubmit={submit} className="provider-form">
      <div className="form-row">
        <select
          value={type}
          onChange={(e) => setType(e.target.value as NewProvider["type"])}
        >
          <option value="localfs">local folder</option>
          <option value="gdrive">Google Drive</option>
          <option value="onedrive">OneDrive</option>
        </select>
        <input
          placeholder="name (e.g. disk-d, my-gdrive)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      {type === "localfs" ? (
        <input
          placeholder="folder path on this machine (e.g. D:\scatterbox)"
          value={root}
          onChange={(e) => setRoot(e.target.value)}
        />
      ) : (
        <>
          <input
            placeholder="OAuth client id"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
          />
          {type === "gdrive" && (
            <input
              type="password"
              placeholder="OAuth client secret"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
            />
          )}
          <p className="muted small">
            Needs your own (free) OAuth app —{" "}
            {type === "gdrive"
              ? "Google Cloud Console, Desktop app client"
              : "Microsoft Entra, personal accounts, http://localhost redirect"}
            . A consent tab will open in your browser; this form waits until
            you finish there.
          </p>
        </>
      )}
      <div className="form-row">
        <button disabled={busy || !name || (type === "localfs" ? !root : !clientId)}>
          {busy
            ? type === "localfs"
              ? "adding…"
              : "waiting for browser consent…"
            : "add provider"}
        </button>
      </div>
      {error && <p className="error small">{error}</p>}
    </form>
  );
}
