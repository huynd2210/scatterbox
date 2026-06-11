import { useEffect, useState } from "react";
import { api } from "../api";
import type { PolicyInfo } from "../types";

/** Placement policy editor for one folder (PLAN.md §7/§11): shows the
 * effective policy and its source, lets the user set or clear an explicit
 * one. Files uploaded under the folder inherit it automatically. */
export function PolicyPanel({ path, onClose }: { path: string; onClose: () => void }) {
  const [info, setInfo] = useState<PolicyInfo | null>(null);
  const [scheme, setScheme] = useState("replica");
  const [replicas, setReplicas] = useState(3);
  const [spread, setSpread] = useState(1);
  const [spreadMode, setSpreadMode] = useState("disjoint");
  const [ecK, setEcK] = useState(3);
  const [ecN, setEcN] = useState(5);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = () => {
    api
      .policy(path)
      .then((p) => {
        setInfo(p);
        setScheme(p.effective.scheme);
        setReplicas(p.effective.replicas);
        setSpread(p.effective.min_spread);
        setSpreadMode(p.effective.spread_mode);
        setEcK(p.effective.ec_k);
        setEcN(p.effective.ec_n);
      })
      .catch((e: Error) => setError(e.message));
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(load, [path]);

  const save = () => {
    setError(null);
    const fields: Record<string, unknown> =
      scheme === "ec"
        ? { scheme, ec_k: ecK, ec_n: ecN }
        : { scheme, replicas, min_spread: spread, spread_mode: spreadMode };
    api
      .setPolicy(path, fields)
      .then(() => {
        setSaved(true);
        setTimeout(() => setSaved(false), 1500);
        load();
      })
      .catch((e: Error) => setError(e.message));
  };

  const clear = () => {
    api
      .clearPolicy(path)
      .then(load)
      .catch((e: Error) => setError(e.message));
  };

  if (info === null) return null;
  const sourceText =
    info.source === null
      ? "defaults"
      : info.source === path
        ? "set on this folder"
        : `inherited from ${info.source}`;

  return (
    <div className="policy-panel">
      <div className="policy-head">
        <strong>policy for {path}</strong>
        <span className="muted small">({sourceText})</span>
        <button className="ghost close" onClick={onClose}>
          ✕
        </button>
      </div>
      <div className="form-row">
        <label>
          scheme
          <select value={scheme} onChange={(e) => setScheme(e.target.value)}>
            <option value="replica">replication</option>
            <option value="ec">erasure coding</option>
          </select>
        </label>
        {scheme === "ec" ? (
          <>
            <label title="data shares — any k rebuild the file">
              k
              <input
                type="number"
                min={1}
                max={20}
                value={ecK}
                onChange={(e) => setEcK(Number(e.target.value))}
              />
            </label>
            <label title="total shares on distinct providers">
              n
              <input
                type="number"
                min={2}
                max={30}
                value={ecN}
                onChange={(e) => setEcN(Number(e.target.value))}
              />
            </label>
            <span className="muted small">
              survives losing {Math.max(ecN - ecK, 0)} provider(s) at {ecN}/{ecK}x
              storage
            </span>
          </>
        ) : (
          <>
            <label title="replica floor per chunk">
              replicas
              <input
                type="number"
                min={1}
                max={9}
                value={replicas}
                onChange={(e) => setReplicas(Number(e.target.value))}
              />
            </label>
            <label title="anti-colocation shard groups (1 = off)">
              spread
              <input
                type="number"
                min={1}
                max={9}
                value={spread}
                onChange={(e) => setSpread(Number(e.target.value))}
              />
            </label>
            {spread > 1 && (
              <label>
                mode
                <select value={spreadMode} onChange={(e) => setSpreadMode(e.target.value)}>
                  <option value="disjoint">disjoint (strongest)</option>
                  <option value="packed">packed (fewest providers)</option>
                </select>
              </label>
            )}
          </>
        )}
      </div>
      <div className="form-row">
        <button onClick={save}>{saved ? "saved ✓" : "set policy"}</button>
        {info.explicit !== null && (
          <button className="ghost" onClick={clear}>
            clear (inherit from parent)
          </button>
        )}
      </div>
      {error && <p className="error small">{error}</p>}
    </div>
  );
}
