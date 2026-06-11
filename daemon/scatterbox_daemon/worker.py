"""Background job worker: the only place the daemon talks to providers.

One asyncio task consumes the register's job queue (upload / delete /
scrub). HTTP handlers enqueue and return immediately — that, not handler
speed, is what keeps the UI responsive while gigabytes move (PLAN.md
principle #2). Job lifecycle and progress are broadcast over the WebSocket
so every open explorer tab tracks the same queue.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from scatterbox import pipeline, portability, scrubber
from scatterbox.errors import ScatterboxError
from scatterbox.placement import policy_from_dict
from scatterbox_daemon.state import DaemonState

_IDLE_POLL_S = 5.0  # fallback poll; normally the wake event fires first
# Auto-snapshot debounce: snapshot the register this long after the last
# mutation settles (PLAN.md §9 "after changes (debounced)"). Module-level so
# tests can shrink it.
SNAPSHOT_DEBOUNCE_S = 20.0


async def run_worker(state: DaemonState) -> None:
    """Consume jobs until cancelled (daemon shutdown)."""
    while True:
        try:
            row = state.register.claim_next_job()
        except Exception:
            # e.g. the register connection was swapped by an import — back
            # off one tick and retry rather than killing the worker
            await asyncio.sleep(0.2)
            continue
        if row is None:
            state.wake.clear()
            try:
                await asyncio.wait_for(state.wake.wait(), timeout=_IDLE_POLL_S)
            except TimeoutError:
                pass
            continue
        await _run_job(state, row)


async def run_snapshotter(state: DaemonState) -> None:
    """Debounced register-snapshot loop: wait for a mutation, let changes
    settle, then push the encrypted register to providers. Skips quietly
    while locked (no master key) — the next unlocked mutation catches up."""
    while True:
        await state.dirty.wait()
        await asyncio.sleep(SNAPSHOT_DEBOUNCE_S)
        state.dirty.clear()
        if state.vault is None:
            continue
        try:
            names = await portability.snapshot_to_providers(state.register, state.vault)
            await state.ws.broadcast({"type": "snapshot", "providers": names})
        except ScatterboxError as exc:
            await state.ws.broadcast({"type": "snapshot", "error": str(exc)})


async def _run_job(state: DaemonState, row) -> None:
    """Dispatch one claimed job to its handler and record/broadcast the
    outcome. A failing job marks itself failed; the worker survives."""
    job_id, kind = row["id"], row["kind"]
    payload = json.loads(row["payload"] or "{}")
    await state.ws.broadcast(
        {"type": "job", "id": job_id, "kind": kind, "state": "running", "payload": payload}
    )
    try:
        handler = _HANDLERS[kind]
    except KeyError:
        state.register.finish_job(job_id, error=f"unknown job kind {kind!r}")
        return
    try:
        result = await handler(state, job_id, payload)
    except Exception as exc:  # a failed job must never kill the worker
        state.register.finish_job(job_id, error=str(exc))
        await state.ws.broadcast(
            {"type": "job", "id": job_id, "kind": kind, "state": "failed",
             "payload": payload, "error": str(exc)}
        )
        return
    state.register.finish_job(job_id, result=result)
    state.dirty.set()  # every successful job mutated the register
    await state.ws.broadcast(
        {"type": "job", "id": job_id, "kind": kind, "state": "done",
         "payload": payload, "result": result}
    )


async def _upload(state: DaemonState, job_id: int, p: dict) -> dict:
    """Run a spooled upload through the core pipeline, streaming per-chunk
    progress to the WebSocket; consumes the spool file either way."""
    if state.vault is None:
        raise ScatterboxError("daemon is locked — unlock before uploading")
    tmp = Path(p["tmp_path"])
    loop = asyncio.get_running_loop()

    def on_progress(done: int, total: int) -> None:
        # called between chunk uploads, on the loop thread — fire-and-forget
        # the broadcast so the pipeline never waits on a slow websocket
        loop.create_task(
            state.ws.broadcast(
                {"type": "job", "id": job_id, "kind": "upload", "state": "running",
                 "payload": p, "done": done, "total": total}
            )
        )

    try:
        result = await pipeline.put_file(
            state.register,
            state.vault.master_key,
            tmp,
            p["vpath"],
            policy=policy_from_dict(p.get("policy", {})),
            secrets=state.vault,
            on_progress=on_progress,
        )
    finally:
        tmp.unlink(missing_ok=True)  # the spool file is consumed either way
    return {
        "vpath": result.vpath,
        "size": result.size,
        "chunks": result.chunk_count,
        "replicas": result.replicas,
        "spread": result.spread,
        "scheme": result.scheme,
    }


async def _delete(state: DaemonState, job_id: int, p: dict) -> dict:
    """Delete a file's replicas (provider I/O) and its register entry."""
    await pipeline.remove_file(state.register, p["vpath"], secrets=state.vault)
    return {"vpath": p["vpath"]}


async def _scrub(state: DaemonState, job_id: int, p: dict) -> dict:
    """Run one scrub cycle (optionally deep / with repair) and report the
    tally the transfers panel shows."""
    report = await scrubber.scrub(
        state.register,
        deep=p.get("deep", False),
        repair=p.get("repair", False),
        probe_limit=p.get("probe_limit"),
        secrets=state.vault,
    )
    return {
        "probed": report.probed,
        "confirmed": report.confirmed,
        "deep_verified": report.deep_verified,
        "marked_suspect": report.marked_suspect,
        "marked_lost": report.marked_lost,
        "repaired": report.repaired,
        "unrepairable": report.unrepairable,
    }


_HANDLERS = {"upload": _upload, "delete": _delete, "scrub": _scrub}


def cleanup_stale_spool(state: DaemonState) -> int:
    """Remove spool files orphaned by a crash (their jobs were reset to
    pending but the temp file may be gone or stale); called at startup
    before the worker starts. Returns count removed."""
    pending_tmp = {
        json.loads(row["payload"] or "{}").get("tmp_path")
        for row in state.register.list_jobs(limit=1000)
        if row["state"] == "pending" and row["kind"] == "upload"
    }
    removed = 0
    for f in state.tmp_dir.glob("upload-*"):
        if str(f) not in pending_tmp:
            try:
                os.remove(f)
                removed += 1
            except OSError:
                pass
    return removed
