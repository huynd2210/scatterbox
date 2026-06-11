"""Key derivation and key wrapping (PLAN.md §10).

The key hierarchy has two levels:

    passphrase --Argon2id--> master key --wraps--> per-file keys --> chunks

- The *master key* is derived from the user's passphrase with Argon2id (a
  deliberately slow, memory-hard hash that makes brute-forcing passphrases
  expensive). It is never stored anywhere; it lives only in memory while
  scatterbox is unlocked.
- Each stored file gets its own random *file key*. The file key encrypts the
  file's chunks; the master key encrypts ("wraps") the file key, and that
  wrapped blob is what sits in the register. So leaking one file's manifest
  never exposes other files, and the register alone is useless without the
  passphrase.
"""

from __future__ import annotations

import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scatterbox.errors import ScatterboxError

KEY_LEN = 32  # 32 bytes = AES-256
NONCE_LEN = 12  # GCM's standard nonce size; must be unique per encryption
# Argon2id work factors: ~3 passes over 64 MiB with 4 lanes. Tuned to take a
# noticeable fraction of a second — slow for an attacker, tolerable for one
# interactive unlock.
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST = 64 * 1024  # KiB
DEFAULT_PARALLELISM = 4

# "Additional authenticated data": not encrypted, but mixed into the GCM tag.
# Binds the wrapped blob to this exact purpose/version, so a blob lifted from
# some other GCM context can never successfully unwrap as a file key.
_WRAP_AAD = b"scatterbox-file-key-v1"


def derive_master_key(
    passphrase: str,
    salt: bytes,
    *,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> bytes:
    """Passphrase -> 32-byte master key, deterministically for a given salt.

    The random salt (stored in the vault file) means two users with the same
    passphrase still get different keys, and rainbow tables don't apply.
    """
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,  # Argon2id: hybrid mode, the recommended variant
    )


def wrap_key(master_key: bytes, key: bytes) -> bytes:
    """Encrypt a file key with the master key.

    Returns nonce || ciphertext+tag. AES-GCM is *authenticated* encryption:
    the 16-byte tag proves the blob wasn't tampered with and that the right
    key is being used — unwrap fails loudly instead of returning garbage.
    """
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(master_key).encrypt(nonce, key, _WRAP_AAD)


def unwrap_key(master_key: bytes, blob: bytes) -> bytes:
    """Reverse of wrap_key: split off the nonce, decrypt, verify the tag."""
    try:
        return AESGCM(master_key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], _WRAP_AAD)
    except InvalidTag as exc:
        # GCM tag mismatch: either the passphrase/master key is wrong or the
        # register row was corrupted. Either way we cannot decrypt this file.
        raise ScatterboxError(
            "failed to unwrap file key: wrong master key or corrupt manifest"
        ) from exc
