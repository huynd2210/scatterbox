# scatterbox web UI

React + Vite + TypeScript explorer for the scatterbox daemon. Three views:

- **files** — virtualized listing (@tanstack/react-virtual), breadcrumbs,
  drag-drop upload (with replicas/spread options), download, move/rename,
  delete, lazy per-row health dots, and a "where is this?" provider panel.
- **transfers** — the daemon's job queue, live over WebSocket with
  per-chunk upload progress.
- **providers** — capacity bars with confidence labels (exact/estimated/
  unknown), reliability, and scrub buttons.

Development: run `scatterbox daemon`, then `npm run dev` here — Vite
proxies `/api` and `/ws` to the daemon. Production: `npm run build`; the
daemon serves `dist/` itself, so `scatterbox daemon` is the whole product.
