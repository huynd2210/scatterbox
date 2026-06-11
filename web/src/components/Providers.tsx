import { useEffect, useState } from "react";
import { api, humanBytes } from "../api";
import type { ProviderInfo } from "../types";

/** Provider dashboard (PLAN.md §11): capacity bars with confidence labels —
 * the UI never pretends to know free space more precisely than it does. */
export function Providers({ refreshKey }: { refreshKey: number }) {
  const [providers, setProviders] = useState<ProviderInfo[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    api.providers().then(setProviders).catch((e: Error) => setMessage(e.message));
  }, [refreshKey]);

  const scrub = (opts: { deep?: boolean; repair?: boolean }) =>
    api
      .scrub(opts)
      .then(({ job_id }) => setMessage(`scrub queued (job ${job_id}) — see transfers`))
      .catch((e: Error) => setMessage(e.message));

  if (providers === null) return <p className="muted empty">loading…</p>;

  return (
    <div className="providers">
      <div className="toolbar">
        <span className="muted">{providers.length} provider(s)</span>
        <div>
          <button onClick={() => scrub({})}>scrub</button>
          <button onClick={() => scrub({ deep: true })}>deep scrub</button>
          <button onClick={() => scrub({ repair: true })}>scrub + repair</button>
        </div>
      </div>
      {message && <p className="muted">{message}</p>}
      {providers.map((p) => (
        <ProviderCard key={p.id} p={p} />
      ))}
      {providers.length === 0 && (
        <p className="muted empty">
          no providers — add one with `scatterbox provider add`
        </p>
      )}
    </div>
  );
}

function ProviderCard({ p }: { p: ProviderInfo }) {
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
