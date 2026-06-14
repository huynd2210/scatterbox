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
  const [email, setEmail] = useState("");
  const [appPassword, setAppPassword] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [namespace, setNamespace] = useState("");
  const [region, setRegion] = useState("");
  const [bucket, setBucket] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string[] | null>(null);

  // koofr recovers with an app password, oracle with an S3 access key pair +
  // namespace/region/bucket, instead of an OAuth client id/secret.
  const missingCreds =
    type === "localfs"
      ? !root
      : type === "koofr"
        ? !email || !appPassword
        : type === "oracle"
          ? !accessKeyId || !secretAccessKey || !namespace || !region || !bucket
          : !clientId;

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
        email: email || undefined,
        app_password: appPassword || undefined,
        access_key_id: accessKeyId || undefined,
        secret_access_key: secretAccessKey || undefined,
        namespace: namespace || undefined,
        region: region || undefined,
        bucket: bucket || undefined,
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
          <option value="dropbox">Dropbox</option>
          <option value="pcloud">pCloud</option>
          <option value="koofr">Koofr</option>
          <option value="oracle">Oracle Object Storage</option>
        </select>
        {type === "localfs" ? (
          <input
            placeholder="the provider's folder path"
            value={root}
            onChange={(e) => setRoot(e.target.value)}
          />
        ) : type === "oracle" ? (
          <>
            <input
              placeholder="Oracle object-storage namespace"
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
            />
            <input
              placeholder="Oracle region (e.g. us-ashburn-1)"
              value={region}
              onChange={(e) => setRegion(e.target.value)}
            />
            <input
              placeholder="Oracle bucket name"
              value={bucket}
              onChange={(e) => setBucket(e.target.value)}
            />
            <input
              placeholder="Oracle Access Key"
              value={accessKeyId}
              onChange={(e) => setAccessKeyId(e.target.value)}
            />
            <input
              type="password"
              placeholder="Oracle Secret Key"
              value={secretAccessKey}
              onChange={(e) => setSecretAccessKey(e.target.value)}
            />
            <p className="muted small">
              Oracle Object Storage uses a Customer Secret Key (an S3 access
              key/secret), not OAuth — no browser consent. Create a fresh one in
              the OCI console if the old one is gone with the machine.
            </p>
            <OracleGuide />
          </>
        ) : type === "koofr" ? (
          <>
            <input
              placeholder="Koofr account email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <input
              type="password"
              placeholder="Koofr app password"
              value={appPassword}
              onChange={(e) => setAppPassword(e.target.value)}
            />
            <p className="muted small">
              Koofr uses an app password (HTTP Basic), not OAuth — no browser
              consent. Generate a fresh one in the Koofr web app if the old is
              gone with the machine.
            </p>
            <KoofrGuide />
          </>
        ) : (
          <>
            <input
              placeholder="OAuth client id"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
            />
            {(type === "gdrive" || type === "pcloud") && (
              <input
                type="password"
                placeholder="OAuth client secret"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
              />
            )}
            <p className="muted small">
              A consent tab will open in your browser; this form waits until
              you finish there. The original OAuth app may be gone along with
              the machine — a freshly created one works just as well.
            </p>
            <OAuthGuide type={type as "gdrive" | "onedrive" | "dropbox" | "pcloud"} />
          </>
        )}
        <input
          type="password"
          placeholder="master passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
        />
        <button disabled={busy || passphrase === "" || missingCreds}>
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

/** Collapsible step-by-step OAuth app setup walkthrough. Bringing your own
 * (free) client app is the price of SDK-free cloud adapters — these are the
 * once-per-account console steps the form's one-line hint can't carry. */
function OAuthGuide({
  type,
}: {
  type: "gdrive" | "onedrive" | "dropbox" | "pcloud";
}) {
  const plural = type === "gdrive" || type === "pcloud"; // id + secret
  return (
    <details className="setup-guide">
      <summary>
        where do I get {plural ? "these" : "this"}? — step-by-step
      </summary>
      {type === "pcloud" ? (
        <>
          <ol>
            <li>
              Open{" "}
              <a href="https://docs.pcloud.com/my_apps/" target="_blank" rel="noreferrer">
                docs.pcloud.com/my_apps
              </a>{" "}
              → <strong>New app</strong>, and sign in with the pCloud account
              whose storage you want to use.
            </li>
            <li>
              Give it any name. Under <em>Redirect URIs</em> add exactly{" "}
              <code>http://127.0.0.1:8422/</code> — pCloud checks this against
              the registered value, so the port is fixed and the trailing
              slash matters.
            </li>
            <li>
              Copy both the <strong>Client ID</strong> and{" "}
              <strong>Client secret</strong> into this form — pCloud is a
              confidential client, so unlike Dropbox/OneDrive it needs the
              secret too.
            </li>
          </ol>
          <p className="muted">
            Submitting opens a pCloud consent tab — approve, and scatterbox
            stores everything in a visible <code>scatterbox/</code> folder at
            your account root (chunks are encrypted before upload). Note pCloud
            grants whole-account access; there is no app-folder sandbox, but
            scatterbox only ever touches that one folder.
          </p>
        </>
      ) : type === "dropbox" ? (
        <>
          <ol>
            <li>
              Open{" "}
              <a href="https://www.dropbox.com/developers/apps" target="_blank" rel="noreferrer">
                dropbox.com/developers/apps
              </a>{" "}
              → <strong>Create app</strong>.
            </li>
            <li>
              Choose <strong>Scoped access</strong>, then access type{" "}
              <strong>App folder</strong> — scatterbox gets its own folder
              under <code>Apps/</code> and can touch nothing else. Any name.
            </li>
            <li>
              <em>Permissions</em> tab: tick{" "}
              <code>files.content.read</code>, <code>files.content.write</code>{" "}
              and <code>files.metadata.read</code>, then <strong>Submit</strong>.
            </li>
            <li>
              <em>Settings</em> tab: under <em>OAuth 2 → Redirect URIs</em>{" "}
              add exactly <code>http://127.0.0.1:8421/</code> — Dropbox
              requires the URI registered verbatim, so the port is fixed and
              the trailing slash matters.
            </li>
            <li>
              Copy the <strong>App key</strong> into this form. No secret
              needed (public client + PKCE), and "Development" status is fine
              — you are the only user of this app.
            </li>
          </ol>
          <p className="muted">
            Submitting opens a Dropbox consent tab — sign in with the account
            whose storage you want to use and approve. scatterbox can only
            touch its own <code>Apps/&lt;app name&gt;/</code> folder (chunks
            are encrypted before upload).
          </p>
        </>
      ) : type === "gdrive" ? (
        <>
          <ol>
            <li>
              Open{" "}
              <a href="https://console.cloud.google.com" target="_blank" rel="noreferrer">
                console.cloud.google.com
              </a>{" "}
              and create (or pick) a project — any name works.
            </li>
            <li>
              <em>APIs &amp; Services → Library</em>: search for{" "}
              <strong>Google Drive API</strong> and enable it.
            </li>
            <li>
              <em>APIs &amp; Services → OAuth consent screen</em>: choose{" "}
              <strong>External</strong>, fill in the required app name and
              email. Then — easy to miss, but required —{" "}
              <strong>
                add the Google account you'll sign in with under Test users
              </strong>{" "}
              (shown under <em>Audience</em> in the new console). Staying in
              "Testing" mode is fine — you are the only user of this app.
            </li>
            <li>
              <em>APIs &amp; Services → Credentials → Create credentials →
              OAuth client ID</em>: application type{" "}
              <strong>Desktop app</strong>. No redirect URI to configure —
              desktop apps may use the loopback address out of the box.
            </li>
            <li>
              Copy the <strong>Client ID</strong> and{" "}
              <strong>Client secret</strong> it shows into this form.
            </li>
          </ol>
          <p className="muted">
            Submitting opens a Google consent tab — sign in with the account
            whose storage you want to use and approve. scatterbox only asks
            for the <code>drive.file</code> scope: it can see nothing but the
            files it creates itself, in a visible <code>scatterbox/</code>{" "}
            folder at your Drive root (chunks are encrypted before upload).
          </p>
          <p className="muted">
            <strong>"Access blocked: … has not completed the Google
            verification process" (Error 403: access_denied)</strong> means
            the account you signed in with isn't on the app's test-user list.
            No waiting or verification will fix it — verification is only for
            publishing an app to the public. Go back to{" "}
            <em>OAuth consent screen → Test users</em> (or <em>Audience</em>),
            add that account, and submit here again — it works immediately.
          </p>
          <p className="muted">
            If it fails with "no refresh token", revoke the app's earlier
            consent at{" "}
            <a href="https://myaccount.google.com/permissions" target="_blank" rel="noreferrer">
              myaccount.google.com/permissions
            </a>{" "}
            and try again.
          </p>
        </>
      ) : (
        <>
          <ol>
            <li>
              Open{" "}
              <a href="https://entra.microsoft.com" target="_blank" rel="noreferrer">
                entra.microsoft.com
              </a>{" "}
              → <em>App registrations</em> → <strong>New registration</strong>.
            </li>
            <li>
              Any name; under <em>Supported account types</em> pick{" "}
              <strong>Personal Microsoft accounts only</strong>.
            </li>
            <li>
              Under <em>Redirect URI</em> select the platform{" "}
              <strong>Public client/native (mobile &amp; desktop)</strong> and
              enter <code>http://localhost</code>.
            </li>
            <li>
              Register, then copy the{" "}
              <strong>Application (client) ID</strong> from the Overview page
              into this form. That's all — personal-account apps are public
              clients, so there is no client secret.
            </li>
          </ol>
          <p className="muted">
            Submitting opens a Microsoft consent tab — sign in with the
            personal account whose OneDrive you want to use and approve.
            scatterbox only asks for the app-folder scope: it can touch
            nothing outside its own <code>Apps/&lt;app name&gt;/</code> folder
            in your OneDrive (chunks are encrypted before upload).
          </p>
          <p className="muted">
            <strong>"The ability to create applications outside of a
            directory has been deprecated"</strong> — personal Microsoft
            accounts now need a free Entra directory (tenant) to hold the app
            registration. Ignore the M365 Developer Program suggestion (it
            only accepts Visual Studio Enterprise subscribers); instead sign
            up at{" "}
            <a href="https://azure.microsoft.com/free" target="_blank" rel="noreferrer">
              azure.microsoft.com/free
            </a>{" "}
            with the same Microsoft account — a card is required for identity
            verification but nothing is charged. That creates a "Default
            Directory"; come back to <em>App registrations</em> inside it and
            register as above. The directory only <em>hosts</em> the app —
            with "Personal Microsoft accounts only" selected, scatterbox
            still signs into your personal OneDrive exactly the same way.
          </p>
        </>
      )}
    </details>
  );
}

/** Koofr's app-password walkthrough — Koofr isn't OAuth, so it gets its own
 * guide: there is no app to register, just a self-serve app password. */
function KoofrGuide() {
  return (
    <details className="setup-guide">
      <summary>where do I get the app password? — step-by-step</summary>
      <ol>
        <li>
          Sign in at{" "}
          <a href="https://app.koofr.net" target="_blank" rel="noreferrer">
            app.koofr.net
          </a>{" "}
          with the Koofr account whose storage you want to use.
        </li>
        <li>
          Open <em>Preferences → Password</em> (the profile menu, top-right),
          and scroll to <strong>App passwords</strong>.
        </li>
        <li>
          Give it a name (e.g. <code>scatterbox</code>) and click{" "}
          <strong>Generate</strong>. Copy the password it shows.
        </li>
        <li>
          Paste your account email and that app password into this form. No
          OAuth app, no client id/secret, no browser consent.
        </li>
      </ol>
      <p className="muted">
        scatterbox stores everything in a visible <code>scatterbox/</code>{" "}
        folder in your Koofr account (chunks are encrypted before upload). App
        passwords are limited-scope and individually revocable: revoke one in
        the same screen and run <em>reauth</em> to swap in a fresh one.
      </p>
    </details>
  );
}

/** Oracle Object Storage's walkthrough — its S3 Compatibility API isn't OAuth:
 * you create a Customer Secret Key (an S3 Access Key + Secret Key) and a
 * bucket, and the namespace + region locate the endpoint. */
function OracleGuide() {
  return (
    <details className="setup-guide">
      <summary>where do I get the Oracle keys? — step-by-step</summary>
      <ol>
        <li>
          In the{" "}
          <a href="https://cloud.oracle.com" target="_blank" rel="noreferrer">
            OCI console
          </a>{" "}
          open <em>Storage → Buckets</em>, create a bucket, and note its{" "}
          <strong>namespace</strong> and <strong>region</strong> (both shown on
          the bucket page).
        </li>
        <li>
          Open your <em>profile → Customer Secret Keys → Generate Secret Key</em>
          ; copy the <strong>Access Key</strong> and the <strong>Secret Key</strong>{" "}
          (the secret is shown once).
        </li>
        <li>
          Paste the namespace, region, bucket, and key/secret into this form. No
          OAuth app, no client id/secret, no browser consent.
        </li>
      </ol>
      <p className="muted">
        scatterbox talks to Oracle's S3 Compatibility API (requests are SigV4
        signed) and stores everything under a <code>scatterbox/</code> key prefix
        in the bucket (chunks are encrypted before upload). The Customer Secret
        Key is revocable: delete it in the same screen and run <em>reauth</em> to
        swap in a fresh key/secret.
      </p>
    </details>
  );
}

/** Add-provider form, shared between the wizard and the providers tab. */
export function ProviderForm({ onAdded }: { onAdded: () => void }) {
  const [type, setType] = useState<NewProvider["type"]>("localfs");
  const [name, setName] = useState("");
  const [root, setRoot] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [email, setEmail] = useState("");
  const [appPassword, setAppPassword] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [namespace, setNamespace] = useState("");
  const [region, setRegion] = useState("");
  const [bucket, setBucket] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // koofr (app password) and oracle (an S3 access key pair + namespace/region/
  // bucket) are secret-backed but not OAuth: no browser consent.
  const missingCreds =
    type === "localfs"
      ? !root
      : type === "koofr"
        ? !email || !appPassword
        : type === "oracle"
          ? !accessKeyId || !secretAccessKey || !namespace || !region || !bucket
          : !clientId;

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
        email: email || undefined,
        app_password: appPassword || undefined,
        access_key_id: accessKeyId || undefined,
        secret_access_key: secretAccessKey || undefined,
        namespace: namespace || undefined,
        region: region || undefined,
        bucket: bucket || undefined,
      })
      .then(() => {
        setName("");
        setRoot("");
        setAppPassword("");
        setSecretAccessKey("");
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
          <option value="dropbox">Dropbox</option>
          <option value="pcloud">pCloud</option>
          <option value="koofr">Koofr</option>
          <option value="oracle">Oracle Object Storage</option>
        </select>
        <input
          placeholder="name (e.g. disk-d, my-gdrive)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      {type === "localfs" ? (
        <>
          <input
            placeholder="folder path on this machine (e.g. D:\scatterbox)"
            value={root}
            onChange={(e) => setRoot(e.target.value)}
          />
          <p className="muted small">
            Any folder that's usually reachable works: a second disk, a USB
            drive, a NAS/network mount. It is created if missing, and only
            encrypted chunks land in it.
          </p>
        </>
      ) : type === "oracle" ? (
        <>
          <input
            placeholder="Oracle object-storage namespace"
            value={namespace}
            onChange={(e) => setNamespace(e.target.value)}
          />
          <input
            placeholder="Oracle region (e.g. us-ashburn-1)"
            value={region}
            onChange={(e) => setRegion(e.target.value)}
          />
          <input
            placeholder="Oracle bucket name"
            value={bucket}
            onChange={(e) => setBucket(e.target.value)}
          />
          <input
            placeholder="Oracle Access Key"
            value={accessKeyId}
            onChange={(e) => setAccessKeyId(e.target.value)}
          />
          <input
            type="password"
            placeholder="Oracle Secret Key"
            value={secretAccessKey}
            onChange={(e) => setSecretAccessKey(e.target.value)}
          />
          <p className="muted small">
            Oracle Object Storage uses a Customer Secret Key (an S3 access
            key/secret), not OAuth — no app to register and no browser consent.
            Create one in the OCI console and paste it here.
          </p>
          <OracleGuide />
        </>
      ) : type === "koofr" ? (
        <>
          <input
            placeholder="Koofr account email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input
            type="password"
            placeholder="Koofr app password"
            value={appPassword}
            onChange={(e) => setAppPassword(e.target.value)}
          />
          <p className="muted small">
            Koofr uses an app password (HTTP Basic), not OAuth — no app to
            register and no browser consent. Generate one in the Koofr web app
            and paste it here.
          </p>
          <KoofrGuide />
        </>
      ) : (
        <>
          <input
            placeholder={
              type === "gdrive"
                ? "OAuth client id (…apps.googleusercontent.com)"
                : type === "dropbox"
                  ? "App key from the Dropbox App Console"
                  : type === "pcloud"
                    ? "Client ID from the pCloud App Console"
                    : "application (client) id from Entra"
            }
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
          />
          {(type === "gdrive" || type === "pcloud") && (
            <input
              type="password"
              placeholder="OAuth client secret"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
            />
          )}
          <p className="muted small">
            {
              {
                gdrive: "Google Drive",
                onedrive: "OneDrive",
                dropbox: "Dropbox",
                pcloud: "pCloud",
              }[type]
            }{" "}
            needs your own free OAuth app (a 5-minute, one-time setup per
            account). Submitting opens a consent tab in your browser; this
            form waits until you finish there.
          </p>
          <OAuthGuide type={type} />
        </>
      )}
      <div className="form-row">
        <button disabled={busy || !name || missingCreds}>
          {busy
            ? type === "localfs" || type === "koofr" || type === "oracle"
              ? "adding…"
              : "waiting for browser consent…"
            : "add provider"}
        </button>
      </div>
      {error && <p className="error small">{error}</p>}
    </form>
  );
}
