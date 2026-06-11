"""The daemon's HTTP/WebSocket surface.

Design rules (PLAN.md §2, §4):
- Browse endpoints answer from the SQLite index only — no provider I/O on
  any GET the explorer issues while navigating.
- Anything that talks to providers (upload, delete, scrub) is a queued job;
  the request returns a job id immediately.
- The vault is unlocked into daemon memory by an explicit POST /api/unlock
  and never written anywhere; /api/lock drops it.
- Binds 127.0.0.1 by default — this is a local daemon, not a server.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

import io
import zipfile

from scatterbox import onboarding, pipeline, portability, vault
from scatterbox.errors import ScatterboxError, VPathNotFoundError, WrongPassphraseError
from scatterbox.providers import create_provider
from scatterbox.register import Register, derive_health
from scatterbox_daemon.state import DaemonState
from scatterbox_daemon.worker import cleanup_stale_spool, run_snapshotter, run_worker


def _state(request: Request) -> DaemonState:
    return request.app.state.sb


def _require_unlocked(state: DaemonState) -> None:
    if state.vault is None:
        # 423 Locked: the explorer shows the unlock screen on this status
        raise HTTPException(status_code=423, detail="daemon is locked")


def create_app(home: Path | str | None = None) -> FastAPI:
    home = Path(
        home or os.environ.get("SCATTERBOX_HOME", str(Path.home() / ".scatterbox"))
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = DaemonState(home=home, register=Register(home / "register.db"))
        rescued = state.register.reset_orphaned_jobs()
        if rescued:
            cleanup_stale_spool(state)
        state.worker = asyncio.create_task(run_worker(state))
        state.snapshotter = asyncio.create_task(run_snapshotter(state))
        app.state.sb = state
        yield
        for task in (state.worker, state.snapshotter):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        state.register.close()

    app = FastAPI(title="scatterbox daemon", lifespan=lifespan)
    # The Vite dev server runs on its own port during UI development; the
    # built UI is served by this app itself and needs no CORS.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- session / first-run setup ----------------------------------------------

    @app.post("/api/init")
    async def init(request: Request, body: dict):
        """First-run setup from the web wizard: create the vault and unlock
        it. The register already exists (opened at startup); the vault file
        is the initialization marker, same rule as the CLI."""
        state = _state(request)
        if (state.home / "vault.json").is_file():
            raise HTTPException(status_code=409, detail="already initialized")
        passphrase = body.get("passphrase", "")
        if len(passphrase) < 1:
            raise HTTPException(status_code=400, detail="passphrase must not be empty")
        state.vault = await asyncio.to_thread(
            vault.create_vault, state.home / "vault.json", passphrase
        )
        return {"initialized": True, "locked": False}

    @app.post("/api/import")
    async def import_backup(
        request: Request,
        files: list[UploadFile],
        passphrase: str = Form(...),
    ):
        """First-run import (the other half of the setup choice): accepts
        the export zip, or vault + register files, or the vault alone —
        which triggers recovery from a provider snapshot. Parts are told
        apart by content, never by filename."""
        state = _state(request)
        if (state.home / "vault.json").is_file():
            raise HTTPException(status_code=409, detail="already initialized")

        vault_bytes: bytes | None = None
        register_blob: bytes | None = None

        def classify(data: bytes) -> None:
            nonlocal vault_bytes, register_blob
            if data.startswith(b"PK\x03\x04"):  # export zip: extract members
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for member in zf.namelist():
                        classify(zf.read(member))
            elif data.startswith((b"SBSNAP1\n", b"SQLite format 3\x00")):
                register_blob = data
            else:
                try:
                    if "kdf" in json.loads(data):
                        vault_bytes = data
                        return
                except (ValueError, UnicodeDecodeError):
                    pass
                raise HTTPException(
                    status_code=400,
                    detail="unrecognized file — expected the export zip, a "
                    "vault.json, or a register snapshot/database",
                )

        for f in files:
            classify(await f.read())
        if vault_bytes is None:
            raise HTTPException(status_code=400, detail="no vault.json among the files")

        # The daemon holds the (empty, pre-init) register open; release it
        # around the file swap and reopen whatever the import installed.
        state.register.close()
        try:
            if register_blob is not None:
                v, count = await asyncio.to_thread(
                    portability.import_archive,
                    state.home,
                    vault_bytes=vault_bytes,
                    register_blob=register_blob,
                    passphrase=passphrase,
                    force=True,  # pre-init register.db is disposable
                )
                source = "files"
            else:
                # vault only: unlock it, then recover from provider snapshots
                tmp = state.home / "vault.json.import"
                tmp.write_bytes(vault_bytes)
                try:
                    v = await asyncio.to_thread(vault.unlock_vault, tmp, passphrase)
                except Exception:
                    tmp.unlink(missing_ok=True)
                    raise
                os.replace(tmp, state.home / "vault.json")
                v.path = state.home / "vault.json"
                count, source = await portability.restore_register_from_snapshot(
                    state.home, v, force=True
                )
        except WrongPassphraseError:
            raise HTTPException(status_code=401, detail="wrong passphrase")
        except ScatterboxError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            state.register = Register(state.home / "register.db")
        state.vault = v  # imported and already unlocked — straight to the explorer
        return {"files": count, "restored_from": source}

    @app.get("/api/export")
    async def export_backup(request: Request):
        """One zip: the always-encrypted vault + an encrypted register
        snapshot. With the passphrase, this is the whole archive."""
        state = _state(request)
        _require_unlocked(state)
        snapshot = portability.encrypt_snapshot(
            portability.register_bytes(state.register), state.vault.master_key
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:  # already compressed
            zf.writestr("register.sbsnap", snapshot)
            zf.writestr("vault.json", (state.home / "vault.json").read_bytes())
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="scatterbox-backup.zip"'
            },
        )

    @app.post("/api/unlock")
    async def unlock(request: Request, body: dict):
        state = _state(request)
        passphrase = body.get("passphrase", "")
        try:
            # Argon2id is deliberately slow — run it off the event loop.
            state.vault = await asyncio.to_thread(
                vault.unlock_vault, state.home / "vault.json", passphrase
            )
        except WrongPassphraseError:
            raise HTTPException(status_code=401, detail="wrong passphrase")
        except ScatterboxError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"locked": False}

    @app.post("/api/lock")
    async def lock(request: Request):
        _state(request).vault = None
        return {"locked": True}

    @app.get("/api/status")
    async def status(request: Request):
        state = _state(request)
        ok, total = state.register.durability_summary()
        jobs = state.register.list_jobs(limit=500)
        return {
            "initialized": (state.home / "vault.json").is_file(),
            "locked": state.vault is None,
            "files": state.register.count_files(),
            "providers": len(state.register.list_providers()),
            "chunks_at_floor": ok,
            "chunks_total": total,
            "jobs_pending": sum(1 for j in jobs if j["state"] in ("pending", "running")),
        }

    # -- VFS (index only — never touches providers) ----------------------------

    @app.get("/api/files")
    async def list_files(request: Request, path: str = "/"):
        state = _state(request)
        try:
            vpath = pipeline.normalize_vpath(path)
            dirs, files = state.register.list_children(vpath)
        except ScatterboxError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "path": vpath,
            "dirs": dirs,
            "files": [
                {
                    "name": row["vpath"].rsplit("/", 1)[1],
                    "vpath": row["vpath"],
                    "size": row["size"],
                    "mtime": row["mtime"],
                }
                for row in files
            ],
        }

    @app.get("/api/file")
    async def file_detail(request: Request, path: str):
        """Stat + health + the "where is this?" provider breakdown."""
        state = _state(request)
        rec = state.register.get_file_with_manifest(pipeline.normalize_vpath(path))
        if rec is None:
            raise HTTPException(status_code=404, detail=f"{path} not found")
        min_live = state.register.min_live_replicas(rec["manifest_id"])
        providers: dict[int, dict] = {}
        for row in state.register.file_provider_summary(rec["manifest_id"]):
            entry = providers.setdefault(
                row["provider_id"],
                {"name": row["name"], "type": row["type"], "states": {}},
            )
            entry["states"][row["state"]] = row["n"]
        return {
            "vpath": rec["vpath"],
            "size": rec["size"],
            "mtime": rec["mtime"],
            "chunk_size": rec["chunk_size"],
            "replica_target": rec["replica_target"],
            "min_spread": rec["min_spread"],
            "health": derive_health(min_live, rec["replica_target"]),
            "min_live": min_live,
            "providers": list(providers.values()),
        }

    @app.post("/api/health")
    async def health_batch(request: Request, body: dict):
        """Health for the explorer's *visible* rows only — the virtualized
        list asks for ~50 paths at a time, never the whole tree."""
        state = _state(request)
        out = {}
        for path in body.get("paths", [])[:200]:
            rec = state.register.get_file_with_manifest(path)
            if rec is None:
                continue
            min_live = state.register.min_live_replicas(rec["manifest_id"])
            out[path] = {
                "health": derive_health(min_live, rec["replica_target"]),
                "min_live": min_live,
                "replica_target": rec["replica_target"],
            }
        return out

    @app.post("/api/move")
    async def move(request: Request, body: dict):
        state = _state(request)
        try:
            moved = pipeline.move_path(state.register, body["src"], body["dst"])
        except ScatterboxError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        state.dirty.set()
        await state.ws.broadcast({"type": "files-changed"})
        return {"moved": moved}

    @app.delete("/api/file")
    async def delete_file(request: Request, path: str):
        """Enqueues a delete job: replica deletion is provider I/O."""
        state = _state(request)
        vpath = pipeline.normalize_vpath(path)
        if state.register.get_file(vpath) is None:
            raise HTTPException(status_code=404, detail=f"{vpath} not found")
        job_id = state.register.add_job("delete", {"vpath": vpath})
        state.wake.set()
        return {"job_id": job_id}

    # -- transfers ---------------------------------------------------------------

    @app.post("/api/upload")
    async def upload(
        request: Request,
        file: UploadFile,
        path: str = Form("/"),
        replicas: int = Form(pipeline.DEFAULT_REPLICAS),
        spread: int = Form(1),
        spread_mode: str = Form("disjoint"),
    ):
        """Spool the body to disk and enqueue — returns before any provider
        sees a byte, which is the no-blocking-uploads gate."""
        state = _state(request)
        _require_unlocked(state)
        try:
            vpath = pipeline.normalize_vpath(path, basename=file.filename or "upload.bin")
            if state.register.get_file(vpath) is not None:
                raise HTTPException(status_code=409, detail=f"{vpath} already exists")
        except ScatterboxError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        tmp = state.tmp_dir / f"upload-{uuid.uuid4().hex}"
        with open(tmp, "wb") as out:
            while chunk := await file.read(1 << 20):
                out.write(chunk)
        job_id = state.register.add_job(
            "upload",
            {
                "tmp_path": str(tmp),
                "vpath": vpath,
                "replicas": replicas,
                "spread": spread,
                "spread_mode": spread_mode,
            },
        )
        state.wake.set()
        return {"job_id": job_id, "vpath": vpath}

    @app.get("/api/download")
    async def download(request: Request, path: str):
        """Reassemble to a temp file, stream it, clean up afterwards.

        Synchronous by design: a download's latency is the response itself,
        so there is nothing to gain from a job — and it blocks only this
        request, never the index-backed browsing endpoints.
        """
        state = _state(request)
        _require_unlocked(state)
        vpath = pipeline.normalize_vpath(path)
        tmp = state.tmp_dir / f"download-{uuid.uuid4().hex}"
        try:
            await pipeline.get_file(state.register, state.vault.master_key, vpath, tmp, secrets=state.vault)
        except VPathNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ScatterboxError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return FileResponse(
            tmp,
            filename=vpath.rsplit("/", 1)[1],
            media_type="application/octet-stream",
            background=BackgroundTask(lambda: tmp.unlink(missing_ok=True)),
        )

    @app.get("/api/jobs")
    async def jobs(request: Request, limit: int = 100):
        state = _state(request)
        return [
            {
                "id": row["id"],
                "kind": row["kind"],
                "state": row["state"],
                "payload": json.loads(row["payload"] or "{}"),
                "result": json.loads(row["result"] or "{}") if row["result"] else None,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in state.register.list_jobs(limit=limit)
        ]

    # -- providers ----------------------------------------------------------------

    @app.get("/api/providers")
    async def providers(request: Request):
        state = _state(request)
        out = []
        for row in state.register.list_providers():
            config = json.loads(row["config"])
            entry = {
                "id": row["id"],
                "name": row["name"],
                "type": row["type"],
                "max_object_bytes": config.get("max_object_bytes"),
                "replicas_held": state.register.replica_count_on_provider(row["id"]),
                "quota": None,
                "reliability": None,
                "error": None,
            }
            try:
                instance = create_provider(row["type"], config, state.vault)
                entry["reliability"] = state.register.get_reliability(
                    row["id"], prior=instance.profile().reliability_prior
                )
                entry["latency_class"] = instance.profile().latency_class
                q = await instance.quota()
                entry["quota"] = {
                    "total": q.total_bytes,
                    "used": q.used_bytes,
                    "confidence": q.confidence,
                }
            except ScatterboxError as exc:
                entry["error"] = str(exc)
            except Exception as exc:  # unreachable provider — show, don't 500
                entry["error"] = f"unreachable: {exc}"
            out.append(entry)
        return out

    @app.post("/api/providers")
    async def add_provider(request: Request, body: dict):
        """Provider onboarding from the web wizard — same shared flow the
        CLI uses. For gdrive/onedrive this opens a consent tab in the
        user's browser (the daemon runs on their machine) and blocks this
        request until the flow completes or times out."""
        state = _state(request)
        name = (body.get("name") or "").strip()
        type_ = body.get("type", "localfs")
        if not name:
            raise HTTPException(status_code=400, detail="provider name required")
        limits = {
            "max_object_bytes": body.get("max_object_bytes") or None,
            "capacity_bytes": body.get("capacity_bytes") or None,
        }
        try:
            if type_ == "localfs":
                root = (body.get("root") or "").strip()
                if not root:
                    raise HTTPException(status_code=400, detail="root directory required")
                onboarding.add_localfs_provider(state.register, name, root=root, **limits)
            elif type_ in onboarding.OAUTH_MODULES:
                _require_unlocked(state)
                client_id = (body.get("client_id") or "").strip()
                if not client_id:
                    raise HTTPException(status_code=400, detail="OAuth client id required")

                def run_onboarding() -> None:
                    # Own register connection: this runs on a worker thread,
                    # and sqlite connections must not cross threads. WAL
                    # makes the second connection to the same file safe.
                    reg = Register(state.home / "register.db")
                    try:
                        onboarding.onboard_oauth_provider(
                            reg,
                            state.vault,
                            name,
                            type_,
                            client_id=client_id,
                            client_secret=(body.get("client_secret") or "").strip() or None,
                            **limits,
                        )
                    finally:
                        reg.close()

                await asyncio.to_thread(run_onboarding)
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"unsupported provider type {type_!r} (localfs, gdrive, onedrive)",
                )
        except ScatterboxError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        state.dirty.set()
        await state.ws.broadcast({"type": "files-changed"})
        return {"name": name, "type": type_}

    @app.delete("/api/providers/{name}")
    async def remove_provider(request: Request, name: str, force: bool = False):
        state = _state(request)
        try:
            row = state.register.get_provider_by_name(name)
            if json.loads(row["config"]).get("secret") is not None:
                _require_unlocked(state)
            dropped = onboarding.remove_provider(
                state.register, name, vault=state.vault, force=force
            )
        except ScatterboxError as exc:
            # replica-guard refusals and unknown names both land here
            raise HTTPException(status_code=409, detail=str(exc))
        state.dirty.set()
        await state.ws.broadcast({"type": "files-changed"})
        return {"removed": name, "replicas_dropped": dropped}

    @app.post("/api/scrub")
    async def scrub(request: Request, body: dict | None = None):
        state = _state(request)
        body = body or {}
        job_id = state.register.add_job(
            "scrub",
            {"deep": bool(body.get("deep")), "repair": bool(body.get("repair"))},
        )
        state.wake.set()
        return {"job_id": job_id}

    # -- websocket ------------------------------------------------------------------

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        state: DaemonState = websocket.app.state.sb
        await state.ws.connect(websocket)
        try:
            while True:
                await websocket.receive_text()  # keepalive pings; content ignored
        except WebSocketDisconnect:
            state.ws.disconnect(websocket)

    # -- static UI (built web/dist, when present) -------------------------------------
    dist = Path(__file__).resolve().parents[2] / "web" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="ui")

    return app
