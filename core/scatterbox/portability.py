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

Snapshot format v2 (also used for encrypted exports):
    b"SBSNAP2\\n" || u16 kdf_len || kdf json || nonce(12)
                  || AES-256-GCM(zstd(register bytes))
encrypted under the master key with a format-binding AAD. The embedded kdf
json (Argon2id salt + work factors — explicitly non-secret) is what makes
COLD recovery possible: passphrase + embedded params re-derive the master
key with no vault file at all. v1 blobs (no kdf header) still decrypt via
the vault path. A plain export is just the raw SQLite database (its own
magic identifies it on import).

Cold recovery (the §9 path the Phase 4 deviation deferred, now real):
re-authenticate ONE provider cold → find() the snapshot by its well-known
name → decrypt with the passphrase → install the register → recreate the
vault with the ORIGINAL salt (so the register's wrapped file keys still
unwrap) → adopt the re-authed credentials. Other OAuth providers are then
one `provider reauth` away.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from pathlib import Path

import zstandard
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox import keys
from scatterbox import vault as vault_mod
from scatterbox.errors import ScatterboxError
from scatterbox.pipeline import load_providers
from scatterbox.providers import Provider, RemoteRef, create_provider
from scatterbox.register import Register
from scatterbox.vault import Vault, unlock_vault

_SNAPSHOT_MAGIC_V1 = b"SBSNAP1\n"
_SNAPSHOT_MAGIC_V2 = b"SBSNAP2\n"
_SNAPSHOT_MAGIC = _SNAPSHOT_MAGIC_V2  # what we write
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SNAPSHOT_AAD_V1 = b"scatterbox-register-snapshot-v1"
_SNAPSHOT_AAD_V2 = b"scatterbox-register-snapshot-v2"
# Vault secret holding where the current provider snapshots live.
SNAPSHOT_SECRET = "register-snapshot"
SNAPSHOT_MIN_TARGETS = 2  # PLAN.md §9: ">=2 of the most reliable providers"
# Fixed, well-known object name so cold recovery can find() a snapshot on a
# provider without any local state. Same-name rewrites are safe: localfs
# replaces atomically, OneDrive replaces on session commit, Drive creates a
# duplicate which the old-generation cleanup then deletes.
SNAPSHOT_OBJECT_NAME = "scatterbox-register-snapshot"


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


def encrypt_snapshot(
    db_bytes: bytes, master_key: bytes, kdf: dict | None = None
) -> bytes:
    """Register bytes -> the portable snapshot blob (see module docstring
    for the format). With kdf (the vault's non-secret Argon2id parameters)
    a v2 blob is written — decryptable from the passphrase alone; without
    it, a legacy v1 blob that needs the vault's master key."""
    compressed = zstandard.ZstdCompressor(level=9).compress(db_bytes)
    nonce = os.urandom(keys.NONCE_LEN)
    if kdf is None:
        return (
            _SNAPSHOT_MAGIC_V1
            + nonce
            + AESGCM(master_key).encrypt(nonce, compressed, _SNAPSHOT_AAD_V1)
        )
    header = json.dumps(kdf).encode("utf-8")
    return (
        _SNAPSHOT_MAGIC_V2
        + len(header).to_bytes(2, "big")
        + header
        + nonce
        + AESGCM(master_key).encrypt(nonce, compressed, _SNAPSHOT_AAD_V2)
    )


def is_snapshot(blob: bytes) -> bool:
    return blob.startswith((_SNAPSHOT_MAGIC_V1, _SNAPSHOT_MAGIC_V2))


def snapshot_kdf(blob: bytes) -> dict | None:
    """The KDF parameters embedded in a v2 snapshot, or None (v1 blobs
    predate cold recovery and need the vault for their key)."""
    if not blob.startswith(_SNAPSHOT_MAGIC_V2):
        return None
    offset = len(_SNAPSHOT_MAGIC_V2)
    header_len = int.from_bytes(blob[offset : offset + 2], "big")
    return json.loads(blob[offset + 2 : offset + 2 + header_len])


def decrypt_snapshot(blob: bytes, master_key: bytes) -> bytes:
    """Snapshot blob (v1 or v2) -> raw register bytes; loud, specific
    errors for a wrong key vs. a file that was never a snapshot."""
    if blob.startswith(_SNAPSHOT_MAGIC_V2):
        offset = len(_SNAPSHOT_MAGIC_V2)
        header_len = int.from_bytes(blob[offset : offset + 2], "big")
        body = blob[offset + 2 + header_len :]
        aad = _SNAPSHOT_AAD_V2
    elif blob.startswith(_SNAPSHOT_MAGIC_V1):
        body = blob[len(_SNAPSHOT_MAGIC_V1) :]
        aad = _SNAPSHOT_AAD_V1
    else:
        raise ScatterboxError("not a scatterbox register snapshot (bad magic)")
    try:
        compressed = AESGCM(master_key).decrypt(
            body[: keys.NONCE_LEN], body[keys.NONCE_LEN :], aad
        )
    except InvalidTag as exc:
        raise ScatterboxError(
            "snapshot does not decrypt: wrong passphrase/master key or corrupt file"
        ) from exc
    return zstandard.ZstdDecompressor().decompress(compressed)


def decrypt_snapshot_with_passphrase(blob: bytes, passphrase: str) -> tuple[bytes, dict]:
    """Cold path: derive the master key from the passphrase + the v2 blob's
    embedded KDF parameters. Returns (register bytes, kdf params)."""
    kdf = snapshot_kdf(blob)
    if kdf is None:
        raise ScatterboxError(
            "this snapshot predates cold recovery (v1, no embedded key "
            "parameters) — recovery needs the vault file (scatterbox "
            "restore --vault)"
        )
    master_key = vault_mod.derive_from_kdf(passphrase, kdf)
    return decrypt_snapshot(blob, master_key), kdf


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
    kdf: dict | None = None,
) -> tuple[Path, Path]:
    """Write the two portability files into dest_dir (PLAN.md §9): the
    register (encrypted snapshot when master_key is given, plain SQLite
    otherwise) and a copy of the always-encrypted vault. Pass the vault's
    kdf params too — the exported snapshot is then importable from the
    passphrase alone (v2)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    data = register_bytes(register)
    if master_key is not None:
        reg_dest = dest_dir / "register.sbsnap"
        reg_dest.write_bytes(encrypt_snapshot(data, master_key, kdf))
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

        if is_snapshot(register_blob):  # v1 or v2 — the vault has the key
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
    data = encrypt_snapshot(register_bytes(register), vault.master_key, vault.kdf)
    handles = load_providers(register, vault)
    if not handles:
        raise ScatterboxError("no providers configured — nowhere to snapshot to")
    handles.sort(key=lambda h: -h.reliability)
    rows = {row["id"]: row for row in register.list_providers()}

    locations: list[dict] = []
    errors: list[str] = []
    for handle in handles:
        if len(locations) >= min_targets:
            break
        try:
            # Fixed name (SNAPSHOT_OBJECT_NAME) so cold recovery can find()
            # it with no local state at all.
            ref = await handle.instance.put(SNAPSHOT_OBJECT_NAME, data)
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
        # With a fixed object name, a same-provider rewrite usually reuses
        # the ref (localfs path / OneDrive item id) — deleting the "old"
        # location would destroy the snapshot just written. Only Drive
        # creates true duplicates worth cleaning up.
        fresh = {
            (loc["type"], json.dumps(loc["config"], sort_keys=True), loc["ref"])
            for loc in locations
        }
        for loc in previous.get("locations", []):
            key = (loc["type"], json.dumps(loc["config"], sort_keys=True), loc["ref"])
            if key in fresh:
                continue
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


# -- cold recovery (passphrase only — no vault, no register) ----------------------


async def find_snapshot(provider: Provider) -> RemoteRef | None:
    """Locate the well-known snapshot object on a provider, if the adapter
    supports discovery (find() is optional — custom adapters may omit it)."""
    finder = getattr(provider, "find", None)
    if finder is None:
        raise ScatterboxError(
            "this provider type cannot search for objects by name (no "
            "find() support) — cold recovery needs one that can"
        )
    return await finder(SNAPSHOT_OBJECT_NAME)


async def recover_register_cold(
    home: Path, passphrase: str, provider: Provider, *, force: bool = False
) -> tuple[Vault, int]:
    """The full §9 cold path: nothing local survives, the user has only
    their passphrase and (re-authenticated) access to one provider.

    find() the snapshot → decrypt via its embedded KDF parameters →
    validate → install register.db → recreate vault.json with the ORIGINAL
    salt, so every wrapped file key in the restored register still unwraps.
    Returns the new unlocked Vault and the recovered file count.

    The recreated vault has no provider credentials yet — the caller adopts
    the one used for recovery (adopt_recovered_credentials) and the user
    re-auths the rest (`provider reauth`).
    """
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    if (home / "vault.json").exists() and not force:
        raise ScatterboxError(
            f"{home} already has a vault — cold recovery is for empty homes "
            "(use restore/import otherwise)"
        )

    ref = await find_snapshot(provider)
    if ref is None:
        raise ScatterboxError(
            f"no '{SNAPSHOT_OBJECT_NAME}' object found on this provider — "
            "was it one of the snapshot targets? Try another provider."
        )
    blob = await provider.get(ref)
    return install_snapshot_blob(home, passphrase, blob, force=force)


def install_snapshot_blob(
    home: Path, passphrase: str, blob: bytes, *, force: bool = False
) -> tuple[Vault, int]:
    """Install a v2 snapshot with no pre-existing vault: decrypt via the
    embedded KDF parameters, validate, write register.db, and recreate
    vault.json with the ORIGINAL salt. Also serves snapshot-only imports
    (a .sbsnap file dropped into the wizard with nothing else)."""
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    db_bytes, kdf = decrypt_snapshot_with_passphrase(blob, passphrase)

    tmp = home / "register.db.recover"
    tmp.write_bytes(db_bytes)
    try:
        files = _validate_register_file(tmp)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    if force:
        (home / "vault.json").unlink(missing_ok=True)
    vault = vault_mod.create_vault(home / "vault.json", passphrase, kdf_params=kdf)
    os.replace(tmp, home / "register.db")
    return vault, files


def adopt_recovered_credentials(
    register: Register,
    vault: Vault,
    type_: str,
    blob: dict,
    *,
    name: str | None = None,
) -> str:
    """Store the token blob from the cold-recovery re-auth under the
    restored register's matching provider row, so that provider works
    immediately. With several rows of the same type the caller must name
    one. Returns the provider name adopted."""
    rows = [
        row
        for row in register.list_providers()
        if row["type"] == type_ and (name is None or row["name"] == name)
    ]
    if not rows:
        raise ScatterboxError(
            f"the restored register has no {type_!r} provider"
            + (f" named {name!r}" if name else "")
        )
    if len(rows) > 1:
        raise ScatterboxError(
            f"the restored register has several {type_!r} providers "
            f"({', '.join(r['name'] for r in rows)}) — pass the name of the "
            "one you re-authenticated"
        )
    row = rows[0]
    secret_name = json.loads(row["config"]).get("secret")
    if secret_name is None:
        raise ScatterboxError(f"provider {row['name']!r} keeps no credentials")
    vault.set_secret(secret_name, blob)
    return row["name"]
