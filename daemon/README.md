# scatterbox daemon

FastAPI shell over `core/scatterbox` — same register, vault, and pipeline
functions the CLI uses (one code path). Adds what the web explorer needs:

- index-only browse endpoints (never touch providers),
- a background job queue (upload/delete/scrub) so provider I/O never blocks
  a request,
- a WebSocket feed (`/ws`) of job lifecycle + progress,
- explicit vault unlock (`POST /api/unlock`) — the master key lives in
  daemon memory only,
- serves the built web UI from `web/dist` when present.

Run it: `scatterbox daemon` (defaults to `127.0.0.1:8420`). API surface and
design rules are documented at the top of `scatterbox_daemon/app.py`; tests
in `tests/test_daemon.py`.
