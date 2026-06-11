"""Data pipeline: chunk → compress → encrypt → hash → replicate (PLAN.md §5).

This is the heart of scatterbox — what actually happens when you `put` or
`get` a file. On the way up, a file is cut into fixed-size chunks, each chunk
is compressed (only if that helps), encrypted with the file's key, hashed,
and uploaded to several providers chosen by the placement engine. On the way
down the same steps run in reverse, trying each replica until one verifies.

Usable as a library — the daemon imports these same functions in Phase 3.
Stored object layout: nonce(12) || AES-256-GCM ciphertext+tag(16).
chunk_hash = BLAKE3 of the stored object (i.e. of the ciphertext), so a
replica can be health-checked *without* decrypting it — no master key needed
for scrubbing. The per-chunk `compressed` flag lives in the (trusted, local)
register rather than in the stored object, so providers learn nothing about
the data, not even whether it compressed.
"""

from __future__ import annotations

import asyncio
import json
import os
import posixpath
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import zstandard
from blake3 import blake3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox import ec, keys, placement
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
from scatterbox.vault import SecretStore

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB plaintext per chunk
CHUNK_OVERHEAD = keys.NONCE_LEN + 16  # nonce + GCM tag added per stored object
SOFT_MAX_FILE_BYTES = 10 * 1024**3  # 10 GB guard rail; --force-large lifts it
DEFAULT_REPLICAS = 3
_ZSTD_LEVEL = 3  # zstd's default-ish sweet spot: decent ratio, fast


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
    """A provider as the pipeline sees it: the live adapter plus the register
    metadata (row id, name, learned reliability) bundled together."""

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
    replicas: int  # replicas per chunk, or n shares for EC
    spread: int = 1  # disjoint provider groups the chunks are split across
    scheme: str = "replica"  # replica | ec


def resolve_policy(register: Register, vpath: str) -> Policy:
    """The folder policy governing vpath (deepest ancestor wins), or the
    defaults. Explicit arguments are merged on top by the caller."""
    found = register.folder_policy_for(vpath)
    return placement.policy_from_dict(found[1]) if found else Policy()


def load_providers(
    register: Register, secrets: SecretStore | None = None
) -> list[ProviderHandle]:
    """Rehydrate every registered provider row into a live adapter handle.

    `secrets` is the unlocked vault; required only when a registered
    provider type keeps credentials there (gdrive/onedrive)."""
    handles = []
    for row in register.list_providers():
        instance = create_provider(row["type"], json.loads(row["config"]), secrets)
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
    """Size chunks down so the stored object fits every target's max_object_bytes.

    E.g. with a Discord-class 10 MB object cap, an 8 MiB chunk fits, but a
    user-requested 16 MiB chunk would be shrunk to cap minus CHUNK_OVERHEAD
    (the stored object is chunk + nonce + tag, so the overhead must fit too).
    """
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
    """Undo a half-finished put: delete whatever was already uploaded."""
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
    secrets: SecretStore | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> PutResult:
    """Store a local file at a virtual path. The write path, start to finish.

    Order of operations matters for crash safety: all chunks are uploaded
    FIRST, and only then is the file recorded in the register (in one
    transaction). A crash mid-put therefore leaves at worst some orphaned
    ciphertext on providers — never a register entry pointing at missing
    chunks. The except block below cleans up those orphans when the failure
    is one we get to see.

    With policy=None the folder policy for vpath applies (PLAN.md §7);
    `replicas` is a per-call override on top of whichever policy won.
    """
    local_path = Path(local_path)
    vpath = normalize_vpath(vpath, basename=local_path.name)
    if policy is None:
        policy = placement.merge_policy(resolve_policy(register, vpath), replicas=replicas)
    elif replicas is not None:
        raise ScatterboxError("pass either policy or replicas, not both")
    if register.get_file(vpath) is not None:
        raise VPathExistsError(f"{vpath} already exists; rm it first")

    size = _file_size(local_path)
    if size > SOFT_MAX_FILE_BYTES and not force_large:
        raise FileTooLargeError(
            f"{local_path} is {size} bytes (> 10 GB soft cap); "
            "pass --force-large to store it anyway"
        )

    # Pick the providers once for the whole file.
    handles = load_providers(register, secrets)
    ec_targets: list[ProviderHandle] = []
    groups: list[list[ProviderHandle]] = []
    if policy.scheme == "ec":
        # ec(k,n): every chunk becomes n shares on n distinct providers.
        # The floor is exactly n — durability extras make no sense here
        # (more redundancy = raise n), hence the slice.
        ec.validate_params(policy.ec_k, policy.ec_n)
        share_estimate = (chunk_size + CHUNK_OVERHEAD) // policy.ec_k + 64
        ec_targets = (
            await placement.select_targets(
                handles,
                Policy(
                    replicas=policy.ec_n,
                    allowed_tiers=policy.allowed_tiers,
                    pinned=policy.pinned,
                    excluded=policy.excluded,
                ),
                share_estimate,
            )
        )[: policy.ec_n]
        # Conservative: treat per-provider object caps as if a whole chunk
        # had to fit, although only a 1/k share lands there.
        eff_chunk_size = _effective_chunk_size(ec_targets, chunk_size)
    else:
        # Replication: one target set per spread group; without spread there
        # is a single group and every chunk goes to the same set; with
        # min_spread > 1 chunks are dealt round-robin across groups so no
        # provider ever assembles a complete (ciphertext) copy.
        groups = await placement.select_spread_groups(
            handles, policy, chunk_size + CHUNK_OVERHEAD
        )
        eff_chunk_size = _effective_chunk_size(
            [t for group in groups for t in group], chunk_size
        )
        if policy.min_spread > 1 and size > 0:
            if size < policy.min_spread:
                raise ScatterboxError(
                    f"{local_path} is only {size} byte(s) — too small to split "
                    f"across {policy.min_spread} provider groups"
                )
            # A file must have at least min_spread chunks for the guarantee to
            # mean anything (a single-chunk file would hand every replica holder
            # the whole file) — shrink the chunk size if needed.
            eff_chunk_size = min(eff_chunk_size, -(-size // policy.min_spread))

    # Fresh random key for this file (see keys.py for why per-file keys).
    file_key = os.urandom(keys.KEY_LEN)
    aes = AESGCM(file_key)
    compressor = zstandard.ZstdCompressor(level=_ZSTD_LEVEL)

    chunk_rows: list[tuple[int, str, int, int, bool, int, list[tuple[int, str]]]] = []
    uploaded: list[tuple[Provider, RemoteRef]] = []
    total_plain = 0
    try:
        with open(local_path, "rb") as f:
            seq = 0
            while True:
                # Stream the file one chunk at a time — a 10 GB file never
                # needs more than one chunk's worth of memory.
                plain = f.read(eff_chunk_size)
                if not plain:
                    break
                compressed = compressor.compress(plain)
                use_compressed = len(compressed) < len(plain)  # skip if incompressible
                payload = compressed if use_compressed else plain
                # Compress BEFORE encrypting — ciphertext looks random and
                # doesn't compress. Fresh nonce per chunk (GCM rule: never
                # reuse a nonce under the same key).
                nonce = os.urandom(keys.NONCE_LEN)
                obj = nonce + aes.encrypt(nonce, payload, None)
                chunk_hash = blake3(obj).hexdigest()
                if policy.scheme == "ec":
                    # n shares to n providers, share i to target i; object
                    # names carry the index so a share is identifiable on
                    # the provider even without the register.
                    shares = ec.split(obj, policy.ec_k, policy.ec_n)
                    refs = await asyncio.gather(
                        *(
                            t.instance.put(f"{chunk_hash}.{i}", shares[i])
                            for i, t in enumerate(ec_targets)
                        )
                    )
                    uploaded.extend(zip((t.instance for t in ec_targets), refs))
                    ref_rows = [
                        (t.id, r.value, i, blake3(shares[i]).hexdigest())
                        for i, (t, r) in enumerate(zip(ec_targets, refs))
                    ]
                    group = 0
                else:
                    # Deal chunks round-robin across the spread groups (one
                    # group = default) and upload to that group concurrently.
                    group = seq % len(groups)
                    targets = groups[group]
                    refs = await asyncio.gather(
                        *(t.instance.put(chunk_hash, obj) for t in targets)
                    )
                    uploaded.extend(zip((t.instance for t in targets), refs))
                    ref_rows = [
                        (t.id, r.value, None, None) for t, r in zip(targets, refs)
                    ]
                chunk_rows.append(
                    (
                        seq,
                        chunk_hash,
                        len(obj),
                        len(plain),
                        use_compressed,
                        group,
                        ref_rows,
                    )
                )
                total_plain += len(plain)
                seq += 1
                if on_progress is not None:
                    # bytes of plaintext fully replicated so far / file size —
                    # the daemon streams this to the transfers panel
                    on_progress(total_plain, size)
    except Exception:
        await _cleanup_uploads(uploaded)
        raise

    is_ec = policy.scheme == "ec"
    file_id = register.insert_file_with_manifest(
        vpath=vpath,
        size=total_plain,
        mtime=os.path.getmtime(local_path),
        scheme="ec" if is_ec else "replica",
        wrapped_file_key=keys.wrap_key(master_key, file_key),
        chunk_size=eff_chunk_size,
        # For EC the per-chunk floor is "all n shares present"; health and
        # repair read k from the manifest for the death threshold.
        replica_target=policy.ec_n if is_ec else policy.replicas,
        chunk_rows=chunk_rows,
        min_spread=1 if is_ec else policy.min_spread,
        spread_cap=1 if is_ec else policy.resolved_spread_cap(),
        ec_k=policy.ec_k if is_ec else None,
        ec_n=policy.ec_n if is_ec else None,
    )
    return PutResult(
        file_id=file_id,
        vpath=vpath,
        size=total_plain,
        chunk_count=len(chunk_rows),
        chunk_size=eff_chunk_size,
        replicas=policy.ec_n if is_ec else min(len(g) for g in groups),
        spread=1 if is_ec else len(groups),
        scheme="ec" if is_ec else "replica",
    )


async def _fetch_ec_chunk(
    register: Register,
    rec,
    chunk,
    instances: dict[int, Provider],
    secrets: SecretStore | None,
) -> bytes:
    """EC read path for one chunk: collect any k verified shares
    (healthiest replicas first, each checked against its share_hash),
    reconstruct, and verify the chunk hash. Failed shares are marked
    suspect and ding reliability, same as failed replicas."""
    k, n = rec["ec_k"], rec["ec_n"]
    shares: dict[int, bytes] = {}
    for replica in register.get_replicas(chunk["id"]):
        if len(shares) >= k:
            break
        if replica["state"] == "lost" or replica["share_index"] is None:
            continue
        if replica["share_index"] in shares:
            continue
        pid = replica["provider_id"]
        if pid not in instances:
            prow = register.get_provider(pid)
            instances[pid] = create_provider(
                prow["type"], json.loads(prow["config"]), secrets
            )
        prior = instances[pid].profile().reliability_prior
        try:
            data = await instances[pid].get(RemoteRef(replica["remote_ref"]))
        except Exception:
            register.set_replica_state(replica["id"], "suspect")
            register.update_reliability(pid, False, prior=prior)
            continue
        if blake3(data).hexdigest() != replica["share_hash"]:
            register.set_replica_state(replica["id"], "suspect")
            register.update_reliability(pid, False, prior=prior)
            continue
        register.mark_replica_verified(replica["id"])
        register.update_reliability(pid, True, prior=prior)
        shares[replica["share_index"]] = data
    if len(shares) < k:
        raise ChunkUnavailableError(
            f"chunk {chunk['seq']} of {rec['vpath']}: only {len(shares)} of "
            f"the {k} shares needed for reconstruction are available"
        )
    obj = ec.join(shares, k, n, chunk["stored_size"])
    if blake3(obj).hexdigest() != chunk["chunk_hash"]:
        # all shares hashed clean individually, so this would mean wrong
        # parameters or a register/share mismatch — never silent corruption
        raise ChunkUnavailableError(
            f"chunk {chunk['seq']} of {rec['vpath']}: reconstruction failed verification"
        )
    return obj


def _decode_chunk(aes: AESGCM, decompressor, chunk, obj: bytes) -> bytes:
    """Decrypt + decompress + size-check one verified stored object."""
    try:
        payload = aes.decrypt(obj[: keys.NONCE_LEN], obj[keys.NONCE_LEN :], None)
    except InvalidTag as exc:
        raise ChunkUnavailableError(
            f"chunk {chunk['seq']}: decryption failed (wrong key or corrupt data)"
        ) from exc
    plain = decompressor.decompress(payload) if chunk["compressed"] else payload
    if len(plain) != chunk["plain_size"]:
        raise ChunkUnavailableError(f"chunk {chunk['seq']}: size mismatch after decode")
    return plain


async def get_file(
    register: Register,
    master_key: bytes,
    vpath: str,
    local_path: Path | str,
    *,
    secrets: SecretStore | None = None,
) -> None:
    """Restore a file: the read path.

    For each chunk, replicas are tried healthiest-first until one passes ALL
    the checks — fetch succeeded, BLAKE3 hash matches, GCM tag verifies,
    decompressed size is right. Every failed attempt marks that replica
    suspect and dings the provider's reliability score, so reads double as
    health observations. Output goes to a .part temp file that is atomically
    renamed only when every byte checked out — the destination never holds a
    partial file.
    """
    vpath = normalize_vpath(vpath)
    rec = register.get_file_with_manifest(vpath)
    if rec is None:
        raise VPathNotFoundError(f"{vpath} not found")

    file_key = keys.unwrap_key(master_key, rec["wrapped_file_key"])
    aes = AESGCM(file_key)
    decompressor = zstandard.ZstdDecompressor()
    instances: dict[int, Provider] = {}  # provider adapters, created lazily

    is_ec = rec["scheme"] == "ec"
    local_path = Path(local_path)
    tmp = local_path.with_name(local_path.name + ".part")
    written = 0
    try:
        with open(tmp, "wb") as out:
            for chunk in register.get_chunks(rec["manifest_id"]):
                if is_ec:
                    obj = await _fetch_ec_chunk(register, rec, chunk, instances, secrets)
                    plain = _decode_chunk(aes, decompressor, chunk, obj)
                    out.write(plain)
                    written += len(plain)
                    continue
                plain = None
                for replica in register.get_replicas(chunk["id"]):
                    if replica["state"] == "lost":
                        continue  # known-dead; not worth a network call
                    pid = replica["provider_id"]
                    if pid not in instances:
                        prow = register.get_provider(pid)
                        instances[pid] = create_provider(
                            prow["type"], json.loads(prow["config"]), secrets
                        )
                    prior = instances[pid].profile().reliability_prior
                    # Four checks below, same pattern each time: on failure,
                    # mark suspect + reliability down + try the next replica.
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
                    # every replica of this chunk failed — the file is
                    # currently unrecoverable
                    raise ChunkUnavailableError(
                        f"chunk {chunk['seq']} of {vpath}: no replica verified"
                    )
                out.write(plain)
                written += len(plain)
        if written != rec["size"]:
            raise ScatterboxError(
                f"reassembled {written} bytes but expected {rec['size']}"
            )
        os.replace(tmp, local_path)  # atomic: appears complete or not at all
    finally:
        # On success the rename already moved it; this only removes leftovers
        # from a failed run.
        tmp.unlink(missing_ok=True)


async def remove_file(
    register: Register, vpath: str, *, secrets: SecretStore | None = None
) -> None:
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
            instances[pid] = create_provider(
                prow["type"], json.loads(prow["config"]), secrets
            )
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
    min_live: int  # stored replicas/shares of the weakest chunk
    replica_target: int  # replica floor, or n for EC
    chunk_count: int
    replica_states: dict[str, int]  # state -> count over all replicas
    scheme: str = "replica"  # replica | ec
    ec_k: int | None = None


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
        health=derive_health(min_live, rec["replica_target"], ec_k=rec["ec_k"]),
        min_live=min_live,
        replica_target=rec["replica_target"],
        chunk_count=len(register.get_chunks(rec["manifest_id"])),
        replica_states=register.replica_state_counts(rec["manifest_id"]),
        scheme=rec["scheme"],
        ec_k=rec["ec_k"],
    )


def list_dir(
    register: Register, vpath: str = "/"
) -> tuple[list[str], list[tuple[str, int]]]:
    """Immediate children of a virtual directory: (subdir names, (file, size)).

    There is no directory table — directories exist only implicitly as path
    prefixes of stored files (like S3). The register answers with two
    indexed range scans, so listing cost scales with the number of children,
    not the size of the archive.
    """
    vpath = normalize_vpath(vpath)
    exact = register.get_file(vpath)
    if exact is not None:
        return [], [(posixpath.basename(vpath), exact["size"])]
    dirs, file_rows = register.list_children(vpath)
    files = [(posixpath.basename(row["vpath"]), row["size"]) for row in file_rows]
    if not dirs and not files and vpath != "/":
        raise VPathNotFoundError(f"{vpath} not found")
    return dirs, files


def move_path(register: Register, src: str, dst: str) -> int:
    """Rename/move a file or a whole directory subtree; returns the number
    of files moved.

    Pure metadata: chunks never move or re-encrypt, only vpaths change.
    A trailing slash on dst (or dst being an existing directory) means
    "move INTO": `mv /a.txt /docs/` -> /docs/a.txt, like a shell mv.
    """
    into = dst.endswith("/")
    src = normalize_vpath(src)
    dst = normalize_vpath(dst)
    if src == "/":
        raise ScatterboxError("cannot move the root directory")
    if dst == src or dst.startswith(src + "/"):
        raise ScatterboxError(f"cannot move {src} into itself")
    if into or register.list_children(dst)[1] or register.list_children(dst)[0]:
        dst = normalize_vpath(dst + "/" + posixpath.basename(src))

    rec = register.get_file(src)
    if rec is not None:  # single file
        if register.get_file(dst) is not None:
            raise VPathExistsError(f"{dst} already exists")
        register.move_file(rec["id"], dst)
        return 1
    # directory: every file under src/ gets its prefix rewritten
    if register.get_file(dst) is not None:
        raise VPathExistsError(f"{dst} already exists (and is a file)")
    moved = register.move_tree(src, dst)
    if moved == 0:
        raise VPathNotFoundError(f"{src} not found")
    return moved


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
    "move_path",
    "load_providers",
    "normalize_vpath",
]
