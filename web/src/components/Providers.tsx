import { useCallback, useEffect, useState } from "react";
import { api, humanBytes } from "../api";
import type { ProviderInfo } from "../types";
import { ProviderForm } from "./Setup";

/** Provider dashboard (PLAN.md §11): capacity bars with confidence labels —
 * the UI never pretends to know free space more precisely than it does. */
export function Providers({ refreshKey }: { refreshKey: number }) {
  const [providers, setProviders] = useState<ProviderInfo[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const refresh = useCallback(() => {
    api.providers().then(setProviders).catch((e: Error) => setMessage(e.message));
  }, []);
  useEffect(refresh, [refresh, refreshKey]);

  const remove = (p: ProviderInfo) => {
    const force =
      p.replicas_held > 0 &&
      confirm(
        `${p.name} still holds ${p.replicas_held} replica(s).\n` +
          "Remove anyway? You should run scrub + repair afterwards.",
      );
    if (p.replicas_held > 0 && !force) return;
    if (p.replicas_held === 0 && !confirm(`remove provider ${p.name}?`)) return;
    api
      .removeProvider(p.name, force)
      .then(refresh)
      .catch((e: Error) => setMessage(e.message));
  };

  const scrub = (opts: { deep?: boolean; repair?: boolean }) =>
    api
      .scrub(opts)
      .then(({ job_id }) => setMessage(`scrub queued (job ${job_id}) — see transfers`))
      .catch((e: Error) => setMessage(e.message));

  const reauth = (p: ProviderInfo, askCreds = false) => {
    const body: {
      client_id?: string;
      client_secret?: string;
      email?: string;
      app_password?: string;
      access_key_id?: string;
      secret_access_key?: string;
    } = {};
    if (p.type === "koofr") {
      // App-password backend: always re-prompt for the new credential (no
      // browser, nothing to reuse) — e.g. after regenerating it in Koofr.
      const email = prompt(`Koofr account email for ${p.name}`);
      if (!email) return;
      const appPassword = prompt("Koofr app password");
      if (!appPassword) return;
      body.email = email;
      body.app_password = appPassword;
      setMessage(`updating credentials for ${p.name}…`);
    } else if (p.type === "tigris") {
      // S3 access-key backend: re-prompt for just the key/secret (no browser);
      // the bucket on the register row is unchanged.
      const accessKeyId = prompt(`Tigris Access Key ID for ${p.name}`);
      if (!accessKeyId) return;
      const secretAccessKey = prompt("Tigris Secret Access Key");
      if (!secretAccessKey) return;
      body.access_key_id = accessKeyId;
      body.secret_access_key = secretAccessKey;
      setMessage(`updating credentials for ${p.name}…`);
    } else {
      // First try reusing the stored client app credentials; the daemon asks
      // for them only when none survive (e.g. right after a cold recovery).
      if (askCreds) {
        const id = prompt(`OAuth client id for ${p.name}`);
        if (!id) return;
        body.client_id = id;
        if (p.type === "gdrive" || p.type === "pcloud") {
          body.client_secret = prompt("OAuth client secret") ?? undefined;
        }
      }
      setMessage(`re-authenticating ${p.name} — check your browser…`);
    }
    api
      .reauthProvider(p.name, body)
      .then(() => {
        setMessage(`re-authenticated ${p.name}`);
        refresh();
      })
      .catch((e: Error) => {
        if (
          p.type !== "koofr" &&
          p.type !== "tigris" &&
          !askCreds &&
          e.message.includes("client id")
        ) {
          reauth(p, true); // no stored credentials — ask the user
        } else {
          setMessage(e.message);
        }
      });
  };

  if (providers === null) return <p className="muted empty">loading…</p>;

  return (
    <div className="providers">
      <div className="toolbar">
        <span className="muted">{providers.length} provider(s)</span>
        <div>
          <button onClick={() => setAdding((a) => !a)}>
            {adding ? "close" : "add provider"}
          </button>
          <button
            onClick={() => location.assign(api.exportUrl)}
            title="download vault + encrypted register snapshot"
          >
            export backup
          </button>
          <button onClick={() => scrub({})}>scrub</button>
          <button onClick={() => scrub({ deep: true })}>deep scrub</button>
          <button onClick={() => scrub({ repair: true })}>scrub + repair</button>
        </div>
      </div>
      {adding && (
        <ProviderForm
          onAdded={() => {
            setAdding(false);
            refresh();
          }}
        />
      )}
      {message && <p className="muted">{message}</p>}
      {providers.map((p) => (
        <ProviderCard
          key={p.id}
          p={p}
          onRemove={() => remove(p)}
          onReauth={
            p.type === "gdrive" ||
            p.type === "onedrive" ||
            p.type === "dropbox" ||
            p.type === "pcloud" ||
            p.type === "koofr" ||
            p.type === "tigris"
              ? () => reauth(p)
              : undefined
          }
        />
      ))}
      {providers.length === 0 && !adding && (
        <p className="muted empty">no providers yet — add one above</p>
      )}
    </div>
  );
}

/** One provider card: capacity bar with its confidence label, learned
 * reliability, replicas held, reauth (OAuth types) and remove actions. */
function ProviderCard({
  p,
  onRemove,
  onReauth,
}: {
  p: ProviderInfo;
  onRemove: () => void;
  onReauth?: () => void;
}) {
  const q = p.quota;
  const frac =
    q && q.total !== null && q.total > 0 ? Math.min(q.used / q.total, 1) : null;
  return (
    <div className="provider-card">
      <div className="provider-head">
        <span>
          <strong>{p.name}</strong> <span className="muted">({p.type})</span>
        </span>
        <span className="muted">
          {p.replicas_held} replica(s) held
          {p.reliability !== null && ` · reliability ${(p.reliability * 100).toFixed(0)}%`}
          {p.latency_class && ` · ${p.latency_class}`}
          {onReauth && (
            <a className="remove" onClick={onReauth} title="re-authenticate (expired/revoked/recovered credentials)">
              {" "}
              reauth
            </a>
          )}
          <a className="danger remove" onClick={onRemove} title="remove provider">
            {" "}
            ✕
          </a>
        </span>
      </div>
      {p.error ? (
        <p className="error small">{p.error}</p>
      ) : q ? (
        <>
          <div className="bar capacity">
            {frac !== null ? (
              <div className="fill" style={{ width: `${frac * 100}%` }} />
            ) : (
              <div className="fill unknown" style={{ width: "100%" }} />
            )}
          </div>
          <span className="muted small">
            {q.total !== null
              ? `${humanBytes(q.total - q.used)} free of ${humanBytes(q.total)}`
              : `${humanBytes(q.used)} used, total unknown`}
            <span className={`confidence ${q.confidence}`}> ({q.confidence})</span>
            {p.max_object_bytes !== null &&
              ` · max object ${humanBytes(p.max_object_bytes)}`}
          </span>
        </>
      ) : null}
    </div>
  );
}
