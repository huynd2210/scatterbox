"""Secret vault (PLAN.md §9).

The vault file holds everything that must never touch disk in plaintext:

- the Argon2id KDF parameters (salt + work factors) needed to re-derive the
  master key from the passphrase,
- an encrypted "check value" used to tell a wrong passphrase apart from a
  right one at unlock time, and
- (v2) the *secrets section*: provider credentials and OAuth tokens, stored
  as one JSON map encrypted as a single AES-256-GCM blob under the master
  key.

The master key itself is never written to disk — it is re-derived on every
unlock. The salt and KDF parameters are safe to expose; without the
passphrase they are useless, and without the master key the secrets blob is
just noise.

v1 vault files (Phase 0, no secrets section) unlock fine and are upgraded to
v2 the first time a secret is written.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox import keys
from scatterbox.errors import ScatterboxError, WrongPassphraseError

# A known plaintext encrypted under the master key at creation time. If a
# later unlock can decrypt it (GCM tag verifies), the derived key — and thus
# the passphrase — must be correct.
_CHECK_PLAINTEXT = b"scatterbox-vault-check-v1"
_CHECK_AAD = b"vault-check"
# AAD for the secrets blob: binds it to this purpose, so e.g. the check value
# can never be passed off as a secrets section or vice versa.
_SECRETS_AAD = b"vault-secrets-v1"
_SALT_LEN = 16


class SecretStore(Protocol):
    """What adapters need from the vault: named JSON-ish secrets.

    A typing.Protocol so tests can use a plain dict-backed fake and the
    providers package never has to import the Vault class.
    """

    def get_secret(self, name: str) -> Any: ...

    def set_secret(self, name: str, value: Any) -> None: ...


@dataclass
class Vault:
    """An unlocked vault: the master key plus the decrypted secrets map.

    Mutating methods persist immediately (atomic replace), so a crash never
    loses a stored credential — and never writes a plaintext one.
    """

    master_key: bytes
    path: Path | None = None  # None = in-memory only (tests)
    _secrets: dict[str, Any] = field(default_factory=dict)

    def get_secret(self, name: str) -> Any:
        """Return the secret's (decrypted) JSON value, or raise."""
        if name not in self._secrets:
            raise ScatterboxError(f"no secret named {name!r} in the vault")
        return self._secrets[name]

    def has_secret(self, name: str) -> bool:
        return name in self._secrets

    def set_secret(self, name: str, value: Any) -> None:
        """Store/replace a secret (any JSON-serializable value) and persist."""
        self._secrets[name] = value
        self._save()

    def delete_secret(self, name: str) -> None:
        """Remove a secret if present (idempotent) and persist."""
        self._secrets.pop(name, None)
        self._save()

    def _save(self) -> None:
        if self.path is None:
            return
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        doc["version"] = 2
        # The whole map is one blob: individual secret names/sizes leak
        # nothing, and there is no per-entry nonce bookkeeping.
        plaintext = json.dumps(self._secrets).encode("utf-8")
        nonce = os.urandom(keys.NONCE_LEN)
        blob = nonce + AESGCM(self.master_key).encrypt(nonce, plaintext, _SECRETS_AAD)
        doc["secrets"] = base64.b64encode(blob).decode()
        # Atomic replace: the vault file is never half-written.
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)


def create_vault(
    path: Path | str,
    passphrase: str,
    *,
    time_cost: int = keys.DEFAULT_TIME_COST,
    memory_cost: int = keys.DEFAULT_MEMORY_COST,
    parallelism: int = keys.DEFAULT_PARALLELISM,
) -> Vault:
    """First-time setup: pick a random salt, derive the master key, write the
    vault JSON. Refuses to overwrite an existing vault (that would orphan
    every already-encrypted file)."""
    path = Path(path)
    if path.exists():
        raise ScatterboxError(f"vault already exists at {path}")
    salt = os.urandom(_SALT_LEN)
    master_key = keys.derive_master_key(
        passphrase,
        salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )
    # Encrypt the check value now so unlock_vault can verify passphrases later.
    nonce = os.urandom(keys.NONCE_LEN)
    check = nonce + AESGCM(master_key).encrypt(nonce, _CHECK_PLAINTEXT, _CHECK_AAD)
    doc = {
        "version": 2,
        "kdf": {
            "algo": "argon2id",
            # bytes can't go in JSON, hence base64
            "salt": base64.b64encode(salt).decode(),
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
        },
        "check": base64.b64encode(check).decode(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return Vault(master_key=master_key, path=path)


def unlock_vault(path: Path | str, passphrase: str) -> Vault:
    """Re-derive the master key using the stored KDF parameters, prove the
    passphrase right by decrypting the check value, then decrypt the secrets
    section (if any — v1 files predate it)."""
    path = Path(path)
    if not path.is_file():
        raise ScatterboxError(f"no vault at {path}; run 'scatterbox init' first")
    doc = json.loads(path.read_text(encoding="utf-8"))
    kdf = doc["kdf"]
    master_key = keys.derive_master_key(
        passphrase,
        base64.b64decode(kdf["salt"]),
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost"],
        parallelism=kdf["parallelism"],
    )
    check = base64.b64decode(doc["check"])
    try:
        # Wrong passphrase -> wrong key -> GCM tag mismatch -> InvalidTag.
        AESGCM(master_key).decrypt(check[: keys.NONCE_LEN], check[keys.NONCE_LEN :], _CHECK_AAD)
    except InvalidTag as exc:
        raise WrongPassphraseError("wrong passphrase") from exc

    secrets: dict[str, Any] = {}
    if "secrets" in doc:
        blob = base64.b64decode(doc["secrets"])
        try:
            plaintext = AESGCM(master_key).decrypt(
                blob[: keys.NONCE_LEN], blob[keys.NONCE_LEN :], _SECRETS_AAD
            )
        except InvalidTag as exc:
            # The check value passed, so the key is right — the secrets
            # section itself is damaged. Refuse loudly rather than silently
            # dropping every stored credential.
            raise ScatterboxError(f"vault secrets section is corrupt in {path}") from exc
        secrets = json.loads(plaintext)
    return Vault(master_key=master_key, path=path, _secrets=secrets)
