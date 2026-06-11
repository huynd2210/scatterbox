"""Data pipeline: chunk → compress → encrypt → hash → replicate (PLAN.md §5).

Usable as a library — the daemon imports these same functions in Phase 3.
Stored object layout: nonce(12) || AES-256-GCM ciphertext+tag(16).
chunk_hash = BLAKE3 of the stored object; the per-chunk `compressed` flag
lives in the (trusted, local) register.
"""

from __future__ import annotations

import asyncio
import json
import os
import posixpath
from dataclasses import dataclass
from pathlib import Path

import zstandard
from blake3 import blake3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox import keys, placement
from scatterbox.errors import (
    ChunkUnavailableError,
    FileTooLargeError,
    ScatterboxError,
    VPathExistsError,
    VPathNotFoundError,
)
from scatterbox.placement import Policy
from scatterbox.providers import Provider, RemoteRef, create_provider
from scatterbox.register import Register, derive_health

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
CHUNK_OVERHEAD = keys.NONCE_LEN + 16  # nonce + GCM tag added per stored object
SOFT_MAX_FILE_BYTES = 10 * 1024**3
DEFAULT_REPLICAS = 3
_ZSTD_LEVEL = 3


def normalize_vpath(vpath: str, *, basename: str | None = None) -> str:
    """Normalize to an absolute virtual path. A trailing slash means
    "directory": the given basename is appended (CLI `put file /docs/`)."""
    if basename is not None and (vpath == "" or vpath.endswith("/")):
        vpath = vpath.rstrip("/") + "/" + basename
    if not vpath.startswith("/"):
        vpath = "/" + vpath
    norm = posixpath.normpath(vpath)
    while norm.startswith("//"):
        norm = norm[1:]
    if ".." in norm.split("/"):
        raise ScatterboxError(f"invalid virtual path: {vpath!r}")
    return norm


@dataclass(frozen=True)
class ProviderHandle:
    id: int
    name: str
    instance: Provider
    reliability: float = 1.0  # learned score, or the profile prior


@dataclass(frozen=True)
class PutResult:
    file_id: int
    vpath: str
    size: int
    chunk_count: int
    chunk_size: int
    replicas: int


def load_providers(register: Register) -> list[ProviderHandle]:
    handles = []
    for row in register.list_providers():
        instance = create_provider(row["type"], json.loads(row["config"]))
        score = json.loads(row["profile"] or "{}").get("reliability_score")
        handles.append(
            ProviderHandle(
                row["id"],
                row["name"],
                instance,
                score if score is not None else instance.profile().reliability_prior,
            )
        )
    return handles


def _file_size(path: Path) -> int:
    return os.path.getsize(path)


def _effective_chunk_size(targets: list[ProviderHandle], chunk_size: int) -> int:
    """Size chunks down so the stored object fits every target's max_object_bytes."""
    limits = [
        h.instance.profile().max_object_bytes
        for h in targets
        if h.instance.profile().max_object_bytes is not None
    ]
    if not limits:
        return chunk_size
    eff = min(chunk_size, min(limits) - CHUNK_OVERHEAD)
    if eff <= 0:
        raise ScatterboxError(
            f"provider max_object_bytes {min(limits)} too small to store any chunk"
        )
    return eff


async def _cleanup_uploads(uploaded: list[tuple[Provider, RemoteRef]]) -> None:
    for provider, ref in uploaded:
        try:
            await provider.delete(ref)
        except Exception:
            pass  # best-effort; orphaned ciphertext is harmless


async def put_file(
    register: Register,
    master_key: bytes,
    local_path: Path | str,
    vpath: str,
    *,
    policy: Policy | None = None,
    replicas: int | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    force_large: bool = False,
) -> PutResult:
    """`replicas` is shorthand for Policy(replicas=...); pass one or the other."""
    if policy is None:
        policy = Policy(replicas=replicas if replicas is not None else DEFAULT_REPLICAS)
    elif replicas is not None:
        raise ScatterboxError("pass either policy or replicas, not both")
    local_path = Path(local_path)
    vpath = normalize_vpath(vpath, basename=local_path.name)
    if register.get_file(vpath) is not None:
        raise VPathExistsError(f"{vpath} already exists; rm it first")

    size = _file_size(local_path)
    if size > SOFT_MAX_FILE_BYTES and not force_large:
        raise FileTooLargeError(
            f"{local_path} is {size} bytes (> 10 GB soft cap); "
            "pass --force-large to store it anyway"
        )

    targets = await placement.select_targets(
        load_providers(register), policy, chunk_size + CHUNK_OVERHEAD
    )
    eff_chunk_size = _effective_chunk_size(targets, chunk_size)

    file_key = os.urandom(keys.KEY_LEN)
    aes = AESGCM(file_key)
    compressor = zstandard.ZstdCompressor(level=_ZSTD_LEVEL)

    chunk_rows: list[tuple[int, str, int, int, bool, list[tuple[int, str]]]] = []
    uploaded: list[tuple[Provider, RemoteRef]] = []
    total_plain = 0
    try:
        with open(local_path, "rb") as f:
            seq = 0
            while True:
                plain = f.read(eff_chunk_size)
                if not plain:
                    break
                compressed = compressor.compress(plain)
                use_compressed = len(compressed) < len(plain)  # skip if incompressible
                payload = compressed if use_compressed else plain
                nonce = os.urandom(keys.NONCE_LEN)
                obj = nonce + aes.encrypt(nonce, payload, None)
                chunk_hash = blake3(obj).hexdigest()
                refs = await asyncio.gather(
                    *(t.instance.put(chunk_hash, obj) for t in targets)
                )
                uploaded.extend(zip((t.instance for t in targets), refs))
                chunk_rows.append(
                    (
                        seq,
                        chunk_hash,
                        len(obj),
                        len(plain),
                        use_compressed,
                        [(t.id, r.value) for t, r in zip(targets, refs)],
                    )
                )
                total_plain += len(plain)
                seq += 1
    except Exception:
        await _cleanup_uploads(uploaded)
        raise

    file_id = register.insert_file_with_manifest(
        vpath=vpath,
        size=total_plain,
        mtime=os.path.getmtime(local_path),
        scheme="replica",
        wrapped_file_key=keys.wrap_key(master_key, file_key),
        chunk_size=eff_chunk_size,
        replica_target=policy.replicas,
        chunk_rows=chunk_rows,
    )
    return PutResult(
        file_id=file_id,
        vpath=vpath,
        size=total_plain,
        chunk_count=len(chunk_rows),
        chunk_size=eff_chunk_size,
        replicas=len(targets),
    )


async def get_file(
    register: Register,
    master_key: bytes,
    vpath: str,
    local_path: Path | str,
) -> None:
    """Fetch each chunk from the first replica that verifies (BLAKE3 + GCM tag),
    marking failed replicas suspect/missing, and reassemble byte-identically."""
    vpath = normalize_vpath(vpath)
    rec = register.get_file_with_manifest(vpath)
    if rec is None:
        raise VPathNotFoundError(f"{vpath} not found")

    file_key = keys.unwrap_key(master_key, rec["wrapped_file_key"])
    aes = AESGCM(file_key)
    decompressor = zstandard.ZstdDecompressor()
    instances: dict[int, Provider] = {}

    local_path = Path(local_path)
    tmp = local_path.with_name(local_path.name + ".part")
    written = 0
    try:
        with open(tmp, "wb") as out:
            for chunk in register.get_chunks(rec["manifest_id"]):
                plain = None
                for replica in register.get_replicas(chunk["id"]):
                    if replica["state"] == "lost":
                        continue
                    pid = replica["provider_id"]
                    if pid not in instances:
                        prow = register.get_provider(pid)
                        instances[pid] = create_provider(
                            prow["type"], json.loads(prow["config"])
                        )
                    prior = instances[pid].profile().reliability_prior
                    try:
                        obj = await instances[pid].get(RemoteRef(replica["remote_ref"]))
                    except Exception:
                        register.set_replica_state(replica["id"], "suspect")
                        register.update_reliability(pid, False, prior=prior)
                        continue
                    if blake3(obj).hexdigest() != chunk["chunk_hash"]:
                        register.set_replica_state(replica["id"], "suspect")
                        register.update_reliability(pid, False, prior=prior)
                        continue
                    try:
                        payload = aes.decrypt(
                            obj[: keys.NONCE_LEN], obj[keys.NONCE_LEN :], None
                        )
                    except InvalidTag:
                        register.set_replica_state(replica["id"], "suspect")
                        register.update_reliability(pid, False, prior=prior)
                        continue
                    candidate = (
                        decompressor.decompress(payload)
                        if chunk["compressed"]
                        else payload
                    )
                    if len(candidate) != chunk["plain_size"]:
                        register.set_replica_state(replica["id"], "suspect")
                        register.update_reliability(pid, False, prior=prior)
                        continue
                    register.mark_replica_verified(replica["id"])
                    register.update_reliability(pid, True, prior=prior)
                    plain = candidate
                    break
                if plain is None:
                    raise ChunkUnavailableError(
                        f"chunk {chunk['seq']} of {vpath}: no replica verified"
                    )
                out.write(plain)
                written += len(plain)
        if written != rec["size"]:
            raise ScatterboxError(
                f"reassembled {written} bytes but expected {rec['size']}"
            )
        os.replace(tmp, local_path)
    finally:
        tmp.unlink(missing_ok=True)


async def remove_file(register: Register, vpath: str) -> None:
    """Best-effort delete of all replicas, then drop the file from the register."""
    vpath = normalize_vpath(vpath)
    rec = register.get_file_with_manifest(vpath)
    if rec is None:
        raise VPathNotFoundError(f"{vpath} not found")
    instances: dict[int, Provider] = {}
    for replica in register.replicas_for_file(rec["file_id"]):
        pid = replica["provider_id"]
        if pid not in instances:
            prow = register.get_provider(pid)
            instances[pid] = create_provider(prow["type"], json.loads(prow["config"]))
        try:
            await instances[pid].delete(RemoteRef(replica["remote_ref"]))
        except Exception:
            pass  # provider may already be gone; the register row is authoritative
    register.delete_file(rec["file_id"])


@dataclass(frozen=True)
class FileStatus:
    vpath: str
    size: int
    health: str  # healthy | degraded | at-risk | lost
    min_live: int  # stored replicas of the weakest chunk
    replica_target: int
    chunk_count: int
    replica_states: dict[str, int]  # state -> count over all replicas


def file_status(register: Register, vpath: str) -> FileStatus:
    """Per-file durability state, derived from its chunks' replica states."""
    vpath = normalize_vpath(vpath)
    rec = register.get_file_with_manifest(vpath)
    if rec is None:
        raise VPathNotFoundError(f"{vpath} not found")
    min_live = register.min_live_replicas(rec["manifest_id"])
    return FileStatus(
        vpath=vpath,
        size=rec["size"],
        health=derive_health(min_live, rec["replica_target"]),
        min_live=min_live,
        replica_target=rec["replica_target"],
        chunk_count=len(register.get_chunks(rec["manifest_id"])),
        replica_states=register.replica_state_counts(rec["manifest_id"]),
    )


def list_dir(
    register: Register, vpath: str = "/"
) -> tuple[list[str], list[tuple[str, int]]]:
    """Immediate children of a virtual directory: (subdir names, (file, size))."""
    vpath = normalize_vpath(vpath)
    exact = register.get_file(vpath)
    if exact is not None:
        return [], [(posixpath.basename(vpath), exact["size"])]
    prefix = "/" if vpath == "/" else vpath + "/"
    dirs: set[str] = set()
    files: list[tuple[str, int]] = []
    for row in register.list_all_files():
        if not row["vpath"].startswith(prefix):
            continue
        rest = row["vpath"][len(prefix) :]
        if "/" in rest:
            dirs.add(rest.split("/", 1)[0])
        else:
            files.append((rest, row["size"]))
    if not dirs and not files and vpath != "/":
        raise VPathNotFoundError(f"{vpath} not found")
    return sorted(dirs), sorted(files)


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_REPLICAS",
    "SOFT_MAX_FILE_BYTES",
    "CHUNK_OVERHEAD",
    "Policy",
    "PutResult",
    "FileStatus",
    "file_status",
    "put_file",
    "get_file",
    "remove_file",
    "list_dir",
    "load_providers",
    "normalize_vpath",
]
