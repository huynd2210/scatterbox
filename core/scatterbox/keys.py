"""Key derivation and key wrapping (PLAN.md §10).

Master key = Argon2id(passphrase, salt). It wraps random per-file keys;
per-file keys encrypt chunks. The master key is never stored.
"""

from __future__ import annotations

import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox.errors import ScatterboxError

KEY_LEN = 32
NONCE_LEN = 12
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST = 64 * 1024  # KiB
DEFAULT_PARALLELISM = 4

_WRAP_AAD = b"scatterbox-file-key-v1"


def derive_master_key(
    passphrase: str,
    salt: bytes,
    *,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def wrap_key(master_key: bytes, key: bytes) -> bytes:
    """AES-256-GCM wrap; returns nonce || ciphertext+tag."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(master_key).encrypt(nonce, key, _WRAP_AAD)


def unwrap_key(master_key: bytes, blob: bytes) -> bytes:
    try:
        return AESGCM(master_key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], _WRAP_AAD)
    except InvalidTag as exc:
        raise ScatterboxError(
            "failed to unwrap file key: wrong master key or corrupt manifest"
        ) from exc
