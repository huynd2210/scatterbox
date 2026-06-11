import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, healthDots, humanBytes } from "../api";
import type { FileDetail, FileEntry, Health, Listing } from "../types";

type Row =
  | { kind: "dir"; name: string }
  | { kind: "file"; entry: FileEntry };

export function FileBrowser({ refreshKey }: { refreshKey: number }) {
  const [path, setPath] = useState("/");
  const [listing, setListing] = useState<Listing | null>(null);
  const [healths, setHealths] = useState<Record<string, Health>>({});
  const [detail, setDetail] = useState<FileDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [replicas, setReplicas] = useState(3);
  const [spread, setSpread] = useState(1);
  const fileInput = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .list(path)
      .then((l) => {
        if (!cancelled) {
          setListing(l);
          setError(null);
        }
      })
      .catch((e: Error) => !cancelled && setError(e.message));
    setHealths({});
    return () => {
      cancelled = true;
    };
  }, [path, refreshKey]);

  const rows: Row[] = listing
    ? [
        ...listing.dirs.map((name) => ({ kind: "dir", name }) as Row),
        ...listing.files.map((entry) => ({ kind: "file", entry }) as Row),
      ]
    : [];

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 34,
    overscan: 20,
  });
  const items = virtualizer.getVirtualItems();

  // Lazy health: fetch only for the rows currently materialized by the
  // virtualizer (PLAN.md §11 — instant browsing even on huge folders).
  const visiblePaths = items
    .map((it) => rows[it.index])
    .filter((r): r is Extract<Row, { kind: "file" }> => r?.kind === "file")
    .map((r) => r.entry.vpath)
    .filter((p) => !(p in healths));
  const visibleKey = visiblePaths.join("|");
  useEffect(() => {
    if (visiblePaths.length === 0) return;
    let cancelled = false;
    api.health(visiblePaths).then((result) => {
      if (!cancelled) setHealths((old) => ({ ...old, ...result }));
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleKey, refreshKey]);

  const upload = useCallback(
    (files: FileList | File[]) => {
      for (const file of Array.from(files)) {
        api
          .upload(file, path, { replicas, spread })
          .catch((e: Error) => setError(`upload ${file.name}: ${e.message}`));
      }
    },
    [path, replicas, spread],
  );

  const crumbs = path === "/" ? [""] : path.split("/");

  return (
    <div
      className={dragging ? "browser dragging" : "browser"}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (e.dataTransfer.files.length) upload(e.dataTransfer.files);
      }}
    >
      <div className="toolbar">
        <nav className="crumbs">
          {crumbs.map((part, i) => {
            const target = crumbs.slice(0, i + 1).join("/") || "/";
            return (
              <span key={target}>
                {i > 0 && <span className="muted"> / </span>}
                <a onClick={() => setPath(target)}>{part || "root"}</a>
              </span>
            );
          })}
        </nav>
        <div className="upload-opts">
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
          <label title="anti-colocation: split across N provider shard groups">
            spread
            <input
              type="number"
              min={1}
              max={9}
              value={spread}
              onChange={(e) => setSpread(Number(e.target.value))}
            />
          </label>
          <button onClick={() => fileInput.current?.click()}>upload</button>
          <input
            ref={fileInput}
            type="file"
            multiple
            hidden
            onChange={(e) => {
              if (e.target.files) upload(e.target.files);
              e.target.value = "";
            }}
          />
        </div>
      </div>
      {error && <p className="error">{error}</p>}

      <div className="list" ref={scrollRef}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {items.map((it) => {
            const row = rows[it.index];
            if (!row) return null;
            return (
              <div
                key={it.key}
                className="row"
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: it.size,
                  transform: `translateY(${it.start}px)`,
                }}
              >
                {row.kind === "dir" ? (
                  <DirRow
                    name={row.name}
                    onOpen={() =>
                      setPath(path === "/" ? `/${row.name}` : `${path}/${row.name}`)
                    }
                  />
                ) : (
                  <FileRow
                    entry={row.entry}
                    health={healths[row.entry.vpath]}
                    onDetail={() =>
                      api.fileDetail(row.entry.vpath).then(setDetail).catch(() => {})
                    }
                    onError={setError}
                  />
                )}
              </div>
            );
          })}
        </div>
        {listing && rows.length === 0 && (
          <p className="muted empty">empty — drop files here to upload</p>
        )}
      </div>

      {detail && <DetailPanel detail={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

function DirRow({ name, onOpen }: { name: string; onOpen: () => void }) {
  return (
    <div className="cells" onDoubleClick={onOpen}>
      <span className="cell name dir" onClick={onOpen}>
        📁 {name}
      </span>
    </div>
  );
}

function FileRow({
  entry,
  health,
  onDetail,
  onError,
}: {
  entry: FileEntry;
  health?: Health;
  onDetail: () => void;
  onError: (message: string) => void;
}) {
  const rename = () => {
    const dst = prompt("move/rename to", entry.vpath);
    if (dst && dst !== entry.vpath)
      api.move(entry.vpath, dst).catch((e: Error) => onError(e.message));
  };
  const del = () => {
    if (confirm(`delete ${entry.vpath}? (removes all replicas)`))
      api.deleteFile(entry.vpath).catch((e: Error) => onError(e.message));
  };
  return (
    <div className="cells">
      <span className="cell name" onClick={onDetail} title="where is this?">
        {entry.name}
      </span>
      <span
        className={`cell health ${health?.health ?? ""}`}
        title={health ? `${health.health} — weakest chunk ${health.min_live}/${health.replica_target} replicas` : ""}
      >
        {health ? healthDots(health.min_live, health.replica_target) : "…"}
      </span>
      <span className="cell size">{humanBytes(entry.size)}</span>
      <span className="cell actions">
        <a href={api.downloadUrl(entry.vpath)} title="download">
          ⬇
        </a>
        <a onClick={rename} title="move/rename">
          ✎
        </a>
        <a onClick={del} title="delete" className="danger">
          ✕
        </a>
      </span>
    </div>
  );
}

function DetailPanel({
  detail,
  onClose,
}: {
  detail: FileDetail;
  onClose: () => void;
}) {
  return (
    <aside className="detail">
      <button className="ghost close" onClick={onClose}>
        ✕
      </button>
      <h3>{detail.vpath}</h3>
      <dl>
        <dt>size</dt>
        <dd>{humanBytes(detail.size)}</dd>
        <dt>health</dt>
        <dd className={`health ${detail.health}`}>
          {healthDots(detail.min_live, detail.replica_target)} {detail.health} (
          {detail.min_live}/{detail.replica_target})
        </dd>
        <dt>chunk size</dt>
        <dd>{humanBytes(detail.chunk_size)}</dd>
        {detail.min_spread > 1 && (
          <>
            <dt>spread</dt>
            <dd>{detail.min_spread} shard groups</dd>
          </>
        )}
      </dl>
      <h4>where is this?</h4>
      <ul className="provider-list">
        {detail.providers.map((p) => (
          <li key={p.name}>
            <span className="mono">{p.name}</span>
            <span className="muted"> ({p.type}) — </span>
            {Object.entries(p.states)
              .map(([state, n]) => `${n} ${state}`)
              .join(", ")}
          </li>
        ))}
      </ul>
    </aside>
  );
}
