"""Secret vault — Phase 0 stub (PLAN.md §9).

Phase 2 replaces this with the full encrypted vault file (master key +
provider credentials/OAuth tokens). For now the file stores only the Argon2id
KDF parameters and an encrypted check value used to verify the passphrase;
the master key is re-derived on unlock and never written to disk.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox import keys
from scatterbox.errors import ScatterboxError, WrongPassphraseError

_CHECK_PLAINTEXT = b"scatterbox-vault-check-v1"
_CHECK_AAD = b"vault-check"
_SALT_LEN = 16


@dataclass
class Vault:
    """Unlocked vault. Phase 2 adds persistent provider secrets."""

    master_key: bytes

    def get_secret(self, name: str) -> bytes:
        raise NotImplementedError("provider credentials land in the vault in Phase 2")

    def set_secret(self, name: str, value: bytes) -> None:
        raise NotImplementedError("provider credentials land in the vault in Phase 2")


def create_vault(
    path: Path | str,
    passphrase: str,
    *,
    time_cost: int = keys.DEFAULT_TIME_COST,
    memory_cost: int = keys.DEFAULT_MEMORY_COST,
    parallelism: int = keys.DEFAULT_PARALLELISM,
) -> Vault:
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
    nonce = os.urandom(keys.NONCE_LEN)
    check = nonce + AESGCM(master_key).encrypt(nonce, _CHECK_PLAINTEXT, _CHECK_AAD)
    doc = {
        "version": 1,
        "kdf": {
            "algo": "argon2id",
            "salt": base64.b64encode(salt).decode(),
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
        },
        "check": base64.b64encode(check).decode(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return Vault(master_key=master_key)


def unlock_vault(path: Path | str, passphrase: str) -> Vault:
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
        AESGCM(master_key).decrypt(check[: keys.NONCE_LEN], check[keys.NONCE_LEN :], _CHECK_AAD)
    except InvalidTag as exc:
        raise WrongPassphraseError("wrong passphrase") from exc
    return Vault(master_key=master_key)
