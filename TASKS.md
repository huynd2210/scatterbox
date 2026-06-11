# TASKS.md — Phase 3: Daemon + Web explorer

**Status: in progress (started 2026-06-11).**
Phase 2 note: code complete; its real-credential gates (real Drive/OneDrive
round-trip, manual revoke-and-heal) remain open and are tracked in PLAN.md
§12 — the user runs them when ready. Nothing in Phase 3 depends on them.

Read `PLAN.md` first (§4 architecture, §11 UX, §12 Phase 3). Build on
`core/scatterbox/` — the daemon imports the same library functions the CLI
uses (one code path); no storage logic in the daemon or the UI.

## 1. Core support work

- **Fast listing:** `Register.list_children(vpath)` — SQL range scan over the
  vpath index (two queries: direct files, distinct first-level subdir names)
  instead of `list_all_files()`'s full-table scan in Python. `pipeline.list_dir`
  switches to it. This is what buys the <100 ms browse gate at 50k files.
- **Move/rename:** `pipeline.move_path(register, src, dst)` — single file or
  whole directory subtree (prefix rewrite), VPathExists checks, one transaction.
- **Job queue CRUD on the register:** add/claim/update/list for the existing
  `jobs` table (pending → running → done/failed, payload JSON, result JSON).
- **Upload progress hook:** optional `on_progress(bytes_done, bytes_total)`
  callback on `put_file` (called per chunk) so the daemon can stream progress.

*Verify:* unit tests incl. a 50k-file index seeded in one transaction —
`list_children` at the root and nested stays well under 100 ms.

## 2. Daemon (FastAPI, `daemon/scatterbox_daemon/`)

Local-only by default (binds 127.0.0.1). Holds the register open and the
vault **in memory only after an explicit unlock**:

- `POST /api/unlock` {passphrase} / `POST /api/lock` / `GET /api/status`
  (locked?, counts, global durability % of chunks at full floor)
- **VFS:** `GET /api/files?path=` (children via list_children),
  `GET /api/file?path=` (stat + health + replica detail: which providers),
  `POST /api/move`, `DELETE /api/file?path=`
- **Health batch:** `POST /api/health` [paths] → per-file health dots (for
  the visible rows of a virtualized list only)
- **Transfers:** `POST /api/upload` (multipart; spools to a temp file,
  enqueues an upload job, returns job id — the request never waits for
  providers), `GET /api/download?path=` (streams the reassembled file),
  job list/inspect `GET /api/jobs`
- **Job worker:** single asyncio consumer in the daemon process; runs
  upload/scrub jobs through the core library; progress + state transitions
  broadcast over WebSocket
- **WebSocket `/ws`:** job created/progress/done/failed events, scrub
  reports — the UI's live feed
- **Providers:** `GET /api/providers` (quota + confidence + reliability +
  replica counts), `POST /api/scrub` (enqueue scrub job, options deep/repair)

*Verify:* API tests via httpx ASGI transport — upload returns before any
provider I/O completes (job-based); locked daemon refuses crypto endpoints;
move/rm/list round-trip; WS receives job lifecycle; health endpoint flips
within one scrub cycle after chaos-provider failure injection.

## 3. Web explorer (`web/`, React + Vite + TypeScript)

Talks to the daemon over HTTP + WS. Pages (simple tabs, no router dep):

- **Files:** breadcrumb navigation, virtualized list (@tanstack/react-virtual),
  drag-drop + button upload, download, rename/move, delete; per-row badges —
  health dots (●●●/●●○/●○○/lost), replica count, size; lazy health fetch for
  visible rows only; "where is this?" detail panel per file listing providers.
- **Transfers:** live job list from /ws (progress bars, states, errors).
- **Providers:** capacity bars **with confidence labels** (exact/estimated/
  unknown — never lie about precision), reliability score, scrub button
  (normal/deep/repair). Unlock screen when the daemon is locked.

*Verify:* `npm run build` clean (strict TS); daemon serves `web/dist` at `/`
so `scatterbox daemon` is the whole product.

## 4. Packaging + CLI

- `scatterbox daemon [--host --port]` CLI command (uvicorn).
- pyproject: add `daemon/scatterbox_daemon` to the hatchling packages list
  (one distribution — not a workspace); new deps: fastapi, uvicorn,
  python-multipart.

## 5. Phase gate (PLAN.md §12)

- [ ] Browse operations <100 ms on a 50k-file index (automated perf test).
- [ ] Uploads never block the UI (upload endpoint returns pre-I/O; worker
  does provider traffic; asserted in API tests).
- [ ] Health/tier badges reflect injected failures within one scrub cycle
  (chaos provider → scrub job → /api/health flips; asserted in API tests).
- [ ] Full suite green, no regressions.

## Constraints

- Simplicity first; the daemon is a thin shell over `core/scatterbox`.
- UI: no component libraries; one CSS file; virtualization is the only
  rendering dependency.
- When done: update PLAN.md §12 and this file.
