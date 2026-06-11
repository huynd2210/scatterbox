"""Portability + recovery (PLAN.md §9, Phase 4).

The register is the crown jewel: without it, chunks scattered across ten
providers are garbage. Two complementary survival mechanisms live here:

- **Export/import** — deliberate moves. Export produces two files (register
  snapshot + vault); import on a fresh machine restores everything: file
  tree, chunk locations, provider access. No re-upload, no re-scan.
- **Provider snapshots** — the automatic safety net. The encrypted register
  is uploaded to the most reliable providers after changes; *where* it was
  put is recorded inside the vault. Recovery therefore needs only the two
  things a user can keep in their head/pocket: the passphrase and the vault
  file — credentials and snapshot locations are both inside it.

Snapshot format (also used for encrypted exports):
    b"SBSNAP1\\n" || nonce(12) || AES-256-GCM(zstd(register bytes))
encrypted under the master key with a format-binding AAD. A plain export is
just the raw SQLite database (its own magic identifies it on import).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
import uuid
from pathlib import Path

import zstandard
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox import keys
from scatterbox.errors import ScatterboxError
from scatterbox.pipeline import load_providers
from scatterbox.providers import RemoteRef, create_provider
from scatterbox.register import Register
from scatterbox.vault import Vault, unlock_vault

_SNAPSHOT_MAGIC = b"SBSNAP1\n"
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SNAPSHOT_AAD = b"scatterbox-register-snapshot-v1"
# Vault secret holding where the current provider snapshots live.
SNAPSHOT_SECRET = "register-snapshot"
SNAPSHOT_MIN_TARGETS = 2  # PLAN.md §9: ">=2 of the most reliable providers"


def register_bytes(register: Register) -> bytes:
    """A consistent point-in-time copy of the register as raw SQLite bytes.

    Uses the SQLite backup API into a memory database — safe while other
    connections (daemon worker, CLI) are mid-transaction in WAL mode.
    """
    mem = sqlite3.connect(":memory:")
    try:
        register.conn.backup(mem)
        return mem.serialize()
    finally:
        mem.close()


def encrypt_snapshot(db_bytes: bytes, master_key: bytes) -> bytes:
    """Register bytes -> the portable snapshot blob (see module docstring
    for the format)."""
    compressed = zstandard.ZstdCompressor(level=9).compress(db_bytes)
    nonce = os.urandom(keys.NONCE_LEN)
    return (
        _SNAPSHOT_MAGIC
        + nonce
        + AESGCM(master_key).encrypt(nonce, compressed, _SNAPSHOT_AAD)
    )


def decrypt_snapshot(blob: bytes, master_key: bytes) -> bytes:
    """Snapshot blob -> raw register bytes; loud, specific errors for a
    wrong key vs. a file that was never a snapshot."""
    if not blob.startswith(_SNAPSHOT_MAGIC):
        raise ScatterboxError("not a scatterbox register snapshot (bad magic)")
    body = blob[len(_SNAPSHOT_MAGIC) :]
    try:
        compressed = AESGCM(master_key).decrypt(
            body[: keys.NONCE_LEN], body[keys.NONCE_LEN :], _SNAPSHOT_AAD
        )
    except InvalidTag as exc:
        raise ScatterboxError(
            "snapshot does not decrypt: wrong passphrase/master key or corrupt file"
        ) from exc
    return zstandard.ZstdDecompressor().decompress(compressed)


def _validate_register_file(path: Path) -> int:
    """Open (running migrations) and count files — proves the bytes are a
    usable register before we commit to them. Returns the file count."""
    reg = Register(path)
    try:
        return reg.count_files()
    finally:
        reg.close()


# -- export ---------------------------------------------------------------------


def export_archive(
    register: Register,
    vault_path: Path,
    dest_dir: Path,
    *,
    master_key: bytes | None = None,
) -> tuple[Path, Path]:
    """Write the two portability files into dest_dir (PLAN.md §9): the
    register (encrypted snapshot when master_key is given, plain SQLite
    otherwise) and a copy of the always-encrypted vault."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    data = register_bytes(register)
    if master_key is not None:
        reg_dest = dest_dir / "register.sbsnap"
        reg_dest.write_bytes(encrypt_snapshot(data, master_key))
    else:
        reg_dest = dest_dir / "register.db"
        reg_dest.write_bytes(data)
    vault_dest = dest_dir / "vault.json"
    shutil.copyfile(vault_path, vault_dest)
    return reg_dest, vault_dest


# -- import ---------------------------------------------------------------------


def import_archive(
    home: Path,
    *,
    vault_bytes: bytes,
    register_blob: bytes,
    passphrase: str,
    force: bool = False,
) -> tuple[Vault, int]:
    """Install an exported register + vault into a scatterbox home.

    Validation order matters: the vault must unlock with the passphrase
    first (that also yields the key for an encrypted register), and the
    register bytes must open as a real database before either file lands in
    its final place — a failed import leaves the home untouched.

    Returns the unlocked Vault and the imported file count.
    """
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    if (home / "vault.json").exists() and not force:
        raise ScatterboxError(
            f"{home} is already initialized — importing would orphan its "
            "current archive (use force to overwrite)"
        )

    tmp_vault = home / "vault.json.import"
    tmp_vault.write_bytes(vault_bytes)
    try:
        vault = unlock_vault(tmp_vault, passphrase)

        if register_blob.startswith(_SNAPSHOT_MAGIC):
            db_bytes = decrypt_snapshot(register_blob, vault.master_key)
        elif register_blob.startswith(_SQLITE_MAGIC):
            db_bytes = register_blob
        else:
            raise ScatterboxError(
                "register file is neither a scatterbox snapshot nor a SQLite database"
            )

        tmp_reg = home / "register.db.import"
        tmp_reg.write_bytes(db_bytes)
        try:
            files = _validate_register_file(tmp_reg)
        except Exception:
            tmp_reg.unlink(missing_ok=True)
            raise
        os.replace(tmp_reg, home / "register.db")
    except Exception:
        tmp_vault.unlink(missing_ok=True)
        raise
    os.replace(tmp_vault, home / "vault.json")
    vault.path = home / "vault.json"  # future secret writes go to the new home
    return vault, files


# -- provider snapshots (the automatic safety net) --------------------------------


async def snapshot_to_providers(
    register: Register,
    vault: Vault,
    *,
    min_targets: int = SNAPSHOT_MIN_TARGETS,
) -> list[str]:
    """Upload the encrypted register to the most reliable providers and
    record the locations in the vault; returns the provider names used.

    Best-effort beyond the first copy: with only one provider configured
    you get one snapshot (better than none); zero successes is an error.
    The previous snapshot's objects are deleted only after the new
    locations are safely in the vault.
    """
    data = encrypt_snapshot(register_bytes(register), vault.master_key)
    handles = load_providers(register, vault)
    if not handles:
        raise ScatterboxError("no providers configured — nowhere to snapshot to")
    handles.sort(key=lambda h: -h.reliability)
    rows = {row["id"]: row for row in register.list_providers()}
    # Unique name per snapshot generation: a provider replacing-by-name
    # cannot corrupt the previous generation mid-upload.
    name = f"register-snapshot-{uuid.uuid4().hex}"

    locations: list[dict] = []
    errors: list[str] = []
    for handle in handles:
        if len(locations) >= min_targets:
            break
        try:
            ref = await handle.instance.put(name, data)
        except Exception as exc:
            errors.append(f"{handle.name}: {exc}")
            continue
        row = rows[handle.id]
        locations.append(
            {
                "name": handle.name,
                "type": row["type"],
                "config": json.loads(row["config"]),
                "ref": ref.value,
            }
        )
    if not locations:
        raise ScatterboxError(
            "register snapshot failed on every provider: " + "; ".join(errors)
        )

    previous = (
        vault.get_secret(SNAPSHOT_SECRET) if vault.has_secret(SNAPSHOT_SECRET) else None
    )
    vault.set_secret(
        SNAPSHOT_SECRET, {"locations": locations, "created_at": time.time()}
    )
    if previous:
        for loc in previous.get("locations", []):
            try:
                provider = create_provider(loc["type"], loc["config"], vault)
                await provider.delete(RemoteRef(loc["ref"]))
            except Exception:
                pass  # stale ciphertext on a provider is harmless
    return [loc["name"] for loc in locations]


async def restore_register_from_snapshot(
    home: Path, vault: Vault, *, force: bool = False
) -> tuple[int, str]:
    """Disaster recovery: rebuild register.db from a provider snapshot,
    using only what the vault knows. Returns (file count, provider name).
    """
    home = Path(home)
    if (home / "register.db").exists() and not force:
        # an existing register might be NEWER than the snapshot — make the
        # caller decide explicitly
        raise ScatterboxError(
            f"{home / 'register.db'} already exists — restoring would "
            "overwrite it (use force)"
        )
    if not vault.has_secret(SNAPSHOT_SECRET):
        raise ScatterboxError(
            "this vault has no register-snapshot locations — no snapshot "
            "was ever taken, or it predates the snapshot feature"
        )
    info = vault.get_secret(SNAPSHOT_SECRET)
    errors: list[str] = []
    for loc in info.get("locations", []):
        try:
            provider = create_provider(loc["type"], loc["config"], vault)
            blob = await provider.get(RemoteRef(loc["ref"]))
            db_bytes = decrypt_snapshot(blob, vault.master_key)
        except Exception as exc:
            errors.append(f"{loc['name']}: {exc}")
            continue
        tmp = home / "register.db.restore"
        tmp.write_bytes(db_bytes)
        try:
            files = _validate_register_file(tmp)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            errors.append(f"{loc['name']}: snapshot invalid: {exc}")
            continue
        os.replace(tmp, home / "register.db")
        return files, loc["name"]
    raise ScatterboxError(
        "no provider snapshot could be restored: " + "; ".join(errors)
    )
