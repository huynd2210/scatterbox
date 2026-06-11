"""Erasure coding: thin wrapper around zfec (PLAN.md §7, Phase 5).

ec(k,n) turns one encrypted chunk into n *shares*, any k of which rebuild
it. Compared to n-replica storage of the same durability, EC stores n/k of
the data instead of n copies — and a provider holding one share holds 1/k
of unreadable ciphertext, so anti-colocation comes built in.

zfec is systematic: the first k shares are the original data blocks, the
remaining n-k are parity. The chunk is zero-padded up to k equal blocks;
the caller keeps the original length (chunks.stored_size) and we slice the
padding back off after reconstruction.
"""

from __future__ import annotations

import zfec

from scatterbox.errors import ScatterboxError

# zfec's GF(2^8) arithmetic caps n at 255; k<n or there is no redundancy.
MAX_N = 255


def validate_params(k: int, n: int) -> None:
    if not 1 <= k < n <= MAX_N:
        raise ScatterboxError(
            f"invalid erasure coding parameters ec({k},{n}): need 1 <= k < n <= {MAX_N}"
        )


def share_size(data_len: int, k: int) -> int:
    return max(-(-data_len // k), 1)  # ceil; 1-byte floor keeps zfec happy on tiny chunks


def split(data: bytes, k: int, n: int) -> list[bytes]:
    """Encode one chunk into n shares (index = list position)."""
    validate_params(k, n)
    size = share_size(len(data), k)
    padded = data.ljust(k * size, b"\x00")
    blocks = [padded[i * size : (i + 1) * size] for i in range(k)]
    return [bytes(b) for b in zfec.Encoder(k, n).encode(blocks)]


def join(shares: dict[int, bytes], k: int, n: int, original_len: int) -> bytes:
    """Rebuild the chunk from any k shares ({share_index: bytes})."""
    validate_params(k, n)
    if len(shares) < k:
        raise ScatterboxError(
            f"need {k} shares to reconstruct, only {len(shares)} available"
        )
    indices = sorted(shares)[:k]
    blocks = [shares[i] for i in indices]
    primary = zfec.Decoder(k, n).decode(blocks, indices)
    return b"".join(bytes(b) for b in primary)[:original_len]


def regenerate(
    shares: dict[int, bytes], k: int, n: int, original_len: int, missing: list[int]
) -> dict[int, bytes]:
    """Recompute specific lost shares from any k surviving ones (repair)."""
    data = join(shares, k, n, original_len)
    fresh = split(data, k, n)
    return {i: fresh[i] for i in missing}
